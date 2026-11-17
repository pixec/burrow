//! Template builds, tags and which nodes hold which build.
//!
//! A build is immutable and named by the digest of its manifest. Tags are an
//! append-only log: a tag resolves to its newest assignment whose build is
//! ready, so a build that is still running or failed never moves one.

use super::{Db, Result, Store};

pub const BUILDING: &str = "building";
pub const READY: &str = "ready";
pub const FAILED: &str = "failed";
/// Dropped by retention, kept so its chunks can be collected.
pub const DROPPED: &str = "dropped";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BuildRow {
    pub id: String,
    /// Empty until the build finishes.
    pub digest: String,
    pub template: String,
    pub status: String,
    /// The canonical manifest, as JSON.
    pub manifest: String,
    pub parent_digest: String,
    /// The node that built it.
    pub node_id: String,
    pub error: String,
    pub created_at_ms: i64,
    pub finished_at_ms: i64,
    /// When it lost its last tag assignment; 0 while it has one. A build
    /// never tagged is untagged from the start.
    pub untagged_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TagRow {
    pub seq: i64,
    pub template: String,
    pub tag: String,
    pub digest: String,
    pub assigned_at_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TemplateRow {
    pub name: String,
    pub created_at_ms: i64,
    /// 0 unless deleted.
    pub deleted_at_ms: i64,
}

/// How [`Store::finish_build`] went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finished {
    Ready,
    /// A build with the same digest already existed; the new row was dropped
    /// in its favour and the tags point at it.
    Existing,
    /// The build was no longer building: failed or finished already.
    NotBuilding,
}

const BUILD_COLUMNS: &str = "id, COALESCE(digest, ''), template, status, manifest, parent_digest,
    node_id, error, created_at, finished_at, untagged_at";

type BuildRaw = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
);

fn build_row(r: BuildRaw) -> BuildRow {
    BuildRow {
        id: r.0,
        digest: r.1,
        template: r.2,
        status: r.3,
        manifest: r.4,
        parent_digest: r.5,
        node_id: r.6,
        error: r.7,
        created_at_ms: r.8,
        finished_at_ms: r.9,
        untagged_at_ms: r.10,
    }
}

/// Marks untagged, at `$1`, every ready build no assignment names any more.
const MARK_UNTAGGED: &str = "UPDATE template_builds SET untagged_at=$1
    WHERE untagged_at=0 AND status=$2 AND digest IS NOT NULL
      AND digest NOT IN (SELECT digest FROM template_tags)";

fn tag_row(r: (i64, String, String, String, i64)) -> TagRow {
    TagRow {
        seq: r.0,
        template: r.1,
        tag: r.2,
        digest: r.3,
        assigned_at_ms: r.4,
    }
}

impl Store {
    /// Records a build starting, creating its template or bringing a deleted
    /// one back.
    pub async fn begin_build(&self, row: &BuildRow) -> Result<()> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "INSERT INTO templates (name, created_at, deleted_at) VALUES ($1, $2, 0)
                 ON CONFLICT (name) DO UPDATE SET deleted_at=0",
            )
            .bind(&row.template)
            .bind(row.created_at_ms)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO template_builds
                   (id, digest, template, status, manifest, parent_digest, node_id, error,
                    created_at, finished_at)
                 VALUES ($1, NULL, $2, $3, '', $4, $5, '', $6, 0)",
            )
            .bind(&row.id)
            .bind(&row.template)
            .bind(BUILDING)
            .bind(&row.parent_digest)
            .bind(&row.node_id)
            .bind(row.created_at_ms)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    /// Marks a build ready under `digest` and assigns `tags` to it, in one
    /// transaction that only succeeds while the build is still building.
    ///
    /// Two builds finishing on the same digest at once race for its unique
    /// index; the loser tries again and finds the winner's row.
    pub async fn finish_build(
        &self,
        id: &str,
        digest: &str,
        manifest: &str,
        tags: &[String],
        now_ms: i64,
    ) -> Result<Finished> {
        match self
            .try_finish_build(id, digest, manifest, tags, now_ms)
            .await
        {
            Err(crate::StoreError::Db(sqlx::Error::Database(err))) if err.is_unique_violation() => {
                self.try_finish_build(id, digest, manifest, tags, now_ms)
                    .await
            }
            outcome => outcome,
        }
    }

    async fn try_finish_build(
        &self,
        id: &str,
        digest: &str,
        manifest: &str,
        tags: &[String],
        now_ms: i64,
    ) -> Result<Finished> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let template: Option<(String,)> = sqlx::query_as(
                "SELECT template FROM template_builds WHERE id=$1 AND status=$2",
            )
            .bind(id)
            .bind(BUILDING)
            .fetch_optional(&mut *tx)
            .await?;
            let Some((template,)) = template else {
                tx.rollback().await?;
                return Ok(Finished::NotBuilding);
            };
            let existing: Option<(String,)> =
                sqlx::query_as("SELECT id FROM template_builds WHERE digest=$1")
                    .bind(digest)
                    .fetch_optional(&mut *tx)
                    .await?;
            let outcome = match existing {
                Some(_) => {
                    sqlx::query("DELETE FROM template_builds WHERE id=$1")
                        .bind(id)
                        .execute(&mut *tx)
                        .await?;
                    sqlx::query(
                        "UPDATE template_builds SET status=$2, finished_at=$3
                         WHERE digest=$1 AND status=$4",
                    )
                    .bind(digest)
                    .bind(READY)
                    .bind(now_ms)
                    .bind(DROPPED)
                    .execute(&mut *tx)
                    .await?;
                    sqlx::query("UPDATE template_builds SET untagged_at=0 WHERE digest=$1")
                        .bind(digest)
                        .execute(&mut *tx)
                        .await?;
                    Finished::Existing
                }
                None => {
                    sqlx::query(
                        "UPDATE template_builds SET digest=$2, manifest=$3, status=$4,
                            finished_at=$5
                         WHERE id=$1 AND status=$6",
                    )
                    .bind(id)
                    .bind(digest)
                    .bind(manifest)
                    .bind(READY)
                    .bind(now_ms)
                    .bind(BUILDING)
                    .execute(&mut *tx)
                    .await?;
                    Finished::Ready
                }
            };
            for tag in tags {
                sqlx::query(
                    "INSERT INTO template_tags (template, tag, digest, assigned_at)
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(&template)
                .bind(tag)
                .bind(digest)
                .bind(now_ms)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(outcome)
        })
    }

    /// Marks a build failed, unless it already finished.
    pub async fn fail_build(&self, id: &str, error: &str, now_ms: i64) -> Result<bool> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE template_builds SET status=$2, error=$3, finished_at=$4
             WHERE id=$1 AND status=$5",
        )
        .bind(id)
        .bind(FAILED)
        .bind(error)
        .bind(now_ms)
        .bind(BUILDING)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done > 0)
    }

    /// Fails every build still building since before `before_ms`: its
    /// orchestrator or node went away mid-build.
    pub async fn fail_stale_builds(&self, before_ms: i64, now_ms: i64) -> Result<usize> {
        let done = on_pool!(self, pool => sqlx::query(
            "UPDATE template_builds SET status=$1, error='abandoned', finished_at=$2
             WHERE status=$3 AND created_at < $4",
        )
        .bind(FAILED)
        .bind(now_ms)
        .bind(BUILDING)
        .bind(before_ms)
        .execute(pool)
        .await
        .map(|done| done.rows_affected()))?;
        Ok(done as usize)
    }

    /// Records a build that is ready from the start: a step of a build, or a
    /// node's template migrated into a build. One that exists already is
    /// kept, brought back if retention had dropped it.
    pub async fn put_ready_build(&self, row: &BuildRow) -> Result<()> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "INSERT INTO templates (name, created_at, deleted_at) VALUES ($1, $2, 0)
                 ON CONFLICT (name) DO NOTHING",
            )
            .bind(&row.template)
            .bind(row.created_at_ms)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO template_builds
                   (id, digest, template, status, manifest, parent_digest, node_id, error,
                    created_at, finished_at, untagged_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, '', $8, $8, $8)
                 ON CONFLICT (digest) DO UPDATE SET status=excluded.status,
                   untagged_at=excluded.untagged_at
                 WHERE template_builds.status=$9",
            )
            .bind(&row.id)
            .bind(&row.digest)
            .bind(&row.template)
            .bind(READY)
            .bind(&row.manifest)
            .bind(&row.parent_digest)
            .bind(&row.node_id)
            .bind(row.created_at_ms)
            .bind(DROPPED)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    pub async fn get_build(&self, digest: &str) -> Result<Option<BuildRow>> {
        let row: Option<BuildRaw> = on_pool!(self, pool => sqlx::query_as(&format!(
            "SELECT {BUILD_COLUMNS} FROM template_builds WHERE digest=$1"
        ))
        .bind(digest)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map(build_row))
    }

    /// Builds of `template`, or of every template, oldest first.
    pub async fn list_builds(&self, template: Option<&str>) -> Result<Vec<BuildRow>> {
        let rows: Vec<BuildRaw> = on_pool!(self, pool => sqlx::query_as(&format!(
            "SELECT {BUILD_COLUMNS} FROM template_builds
             WHERE $1 = '' OR template = $1
             ORDER BY created_at, id"
        ))
        .bind(template.unwrap_or_default())
        .fetch_all(pool)
        .await)?;
        Ok(rows.into_iter().map(build_row).collect())
    }

    /// Every tag assignment of `template`, or of every template, oldest
    /// first.
    pub async fn list_tags(&self, template: Option<&str>) -> Result<Vec<TagRow>> {
        let rows: Vec<(i64, String, String, String, i64)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT seq, template, tag, digest, assigned_at FROM template_tags
             WHERE $1 = '' OR template = $1
             ORDER BY seq",
        )
        .bind(template.unwrap_or_default())
        .fetch_all(pool)
        .await)?;
        Ok(rows.into_iter().map(tag_row).collect())
    }

    pub async fn list_templates(&self) -> Result<Vec<TemplateRow>> {
        let rows: Vec<(String, i64, i64)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT name, created_at, deleted_at FROM templates ORDER BY name",
        )
        .fetch_all(pool)
        .await)?;
        Ok(rows
            .into_iter()
            .map(|r| TemplateRow {
                name: r.0,
                created_at_ms: r.1,
                deleted_at_ms: r.2,
            })
            .collect())
    }

    /// The build `template:tag` names: its newest assignment whose build is
    /// ready.
    pub async fn resolve_tag(&self, template: &str, tag: &str) -> Result<Option<String>> {
        let row: Option<(String,)> = on_pool!(self, pool => sqlx::query_as(
            "SELECT t.digest FROM template_tags t
             JOIN template_builds b ON b.digest = t.digest
             JOIN templates n ON n.name = t.template
             WHERE t.template=$1 AND t.tag=$2 AND b.status=$3 AND n.deleted_at=0
             ORDER BY t.seq DESC LIMIT 1",
        )
        .bind(template)
        .bind(tag)
        .bind(READY)
        .fetch_optional(pool)
        .await)?;
        Ok(row.map(|(digest,)| digest))
    }

    /// Points `template:tag` at `digest`, a ready build.
    pub async fn assign_tag(
        &self,
        template: &str,
        tag: &str,
        digest: &str,
        now_ms: i64,
    ) -> Result<()> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            sqlx::query(
                "INSERT INTO templates (name, created_at, deleted_at) VALUES ($1, $2, 0)
                 ON CONFLICT (name) DO UPDATE SET deleted_at=0",
            )
            .bind(template)
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO template_tags (template, tag, digest, assigned_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(template)
            .bind(tag)
            .bind(digest)
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE template_builds SET untagged_at=0 WHERE digest=$1")
                .bind(digest)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(())
        })
    }

    /// Removes every assignment of `template:tag`. Returns how many.
    pub async fn delete_tag(&self, template: &str, tag: &str, now_ms: i64) -> Result<usize> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let done = sqlx::query("DELETE FROM template_tags WHERE template=$1 AND tag=$2")
                .bind(template)
                .bind(tag)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            sqlx::query(MARK_UNTAGGED)
                .bind(now_ms)
                .bind(READY)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(done as usize)
        })
    }

    /// Deletes a template: its tags go, and its builds are left untagged for
    /// retention to drop. False when there is no such template.
    pub async fn delete_template(&self, name: &str, now_ms: i64) -> Result<bool> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let done = sqlx::query(
                "UPDATE templates SET deleted_at=$2 WHERE name=$1 AND deleted_at=0",
            )
            .bind(name)
            .bind(now_ms)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM template_tags WHERE template=$1")
                .bind(name)
                .execute(&mut *tx)
                .await?;
            sqlx::query(MARK_UNTAGGED)
                .bind(now_ms)
                .bind(READY)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(done.rows_affected() > 0)
        })
    }

    /// Drops assignments beyond the newest `keep` of each tag.
    pub async fn prune_tags(&self, keep: usize, now_ms: i64) -> Result<usize> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            let done = sqlx::query(
                "DELETE FROM template_tags WHERE seq IN (
                    SELECT seq FROM (
                        SELECT seq, ROW_NUMBER() OVER (PARTITION BY template, tag ORDER BY seq DESC) AS n
                        FROM template_tags
                    ) ranked WHERE n > $1
                )",
            )
            .bind(keep as i64)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            sqlx::query(MARK_UNTAGGED)
                .bind(now_ms)
                .bind(READY)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            Ok(done as usize)
        })
    }

    /// Marks builds dropped by retention, leaving their rows for the chunk
    /// collector.
    pub async fn drop_builds(&self, digests: &[String], now_ms: i64) -> Result<usize> {
        let mut dropped = 0;
        for digest in digests {
            let done = on_pool!(self, pool => sqlx::query(
                "UPDATE template_builds SET status=$2, finished_at=$3
                 WHERE digest=$1 AND status<>$2",
            )
            .bind(digest)
            .bind(DROPPED)
            .bind(now_ms)
            .execute(pool)
            .await
            .map(|done| done.rows_affected()))?;
            dropped += done as usize;
        }
        Ok(dropped)
    }

    /// Replaces what `node_id` is recorded as holding.
    pub async fn replace_node_builds(
        &self,
        node_id: &str,
        digests: &[String],
        now_ms: i64,
    ) -> Result<()> {
        on_pool!(self, pool => {
            let mut tx = pool.begin().await?;
            sqlx::query("DELETE FROM node_builds WHERE node_id=$1")
                .bind(node_id)
                .execute(&mut *tx)
                .await?;
            for digest in digests {
                sqlx::query(
                    "INSERT INTO node_builds (node_id, digest, seen_at) VALUES ($1, $2, $3)
                     ON CONFLICT DO NOTHING",
                )
                .bind(node_id)
                .bind(digest)
                .bind(now_ms)
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(())
        })
    }

    /// Every (node, build digest) the nodes last reported.
    pub async fn list_node_builds(&self) -> Result<Vec<(String, String)>> {
        Ok(on_pool!(self, pool => sqlx::query_as(
            "SELECT node_id, digest FROM node_builds ORDER BY node_id, digest",
        )
        .fetch_all(pool)
        .await)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn building(id: &str, template: &str, at: i64) -> BuildRow {
        BuildRow {
            id: id.into(),
            template: template.into(),
            created_at_ms: at,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_tag_moves_only_to_a_ready_build() {
        let store = Store::open_in_memory().await.unwrap();
        store.begin_build(&building("b1", "py", 1)).await.unwrap();
        assert_eq!(store.resolve_tag("py", "latest").await.unwrap(), None);
        let tags = vec!["latest".to_string()];
        assert_eq!(
            store
                .finish_build("b1", "sha256:a", "{}", &tags, 2)
                .await
                .unwrap(),
            Finished::Ready
        );
        assert_eq!(
            store.resolve_tag("py", "latest").await.unwrap().as_deref(),
            Some("sha256:a")
        );

        store.begin_build(&building("b2", "py", 3)).await.unwrap();
        assert!(store.fail_build("b2", "step failed", 4).await.unwrap());
        assert_eq!(
            store
                .finish_build("b2", "sha256:b", "{}", &tags, 5)
                .await
                .unwrap(),
            Finished::NotBuilding
        );
        assert_eq!(
            store.resolve_tag("py", "latest").await.unwrap().as_deref(),
            Some("sha256:a")
        );

        store.begin_build(&building("b3", "py", 6)).await.unwrap();
        store
            .finish_build("b3", "sha256:c", "{}", &tags, 7)
            .await
            .unwrap();
        assert_eq!(
            store.resolve_tag("py", "latest").await.unwrap().as_deref(),
            Some("sha256:c")
        );
        // Rolling back is a new assignment.
        store
            .assign_tag("py", "latest", "sha256:a", 8)
            .await
            .unwrap();
        assert_eq!(
            store.resolve_tag("py", "latest").await.unwrap().as_deref(),
            Some("sha256:a")
        );
        assert_eq!(store.list_tags(Some("py")).await.unwrap().len(), 3);
        // A dropped build no longer resolves; the tag falls back.
        store
            .drop_builds(&["sha256:a".to_string()], 9)
            .await
            .unwrap();
        assert_eq!(
            store.resolve_tag("py", "latest").await.unwrap().as_deref(),
            Some("sha256:c")
        );
    }

    #[tokio::test]
    async fn an_identical_build_is_folded_into_the_existing_one() {
        let store = Store::open_in_memory().await.unwrap();
        let tags = vec!["latest".to_string()];
        store.begin_build(&building("b1", "py", 1)).await.unwrap();
        store
            .finish_build("b1", "sha256:a", "{}", &tags, 2)
            .await
            .unwrap();
        store.begin_build(&building("b2", "py", 3)).await.unwrap();
        assert_eq!(
            store
                .finish_build("b2", "sha256:a", "{}", &["v2".to_string()], 4)
                .await
                .unwrap(),
            Finished::Existing
        );
        let builds = store.list_builds(Some("py")).await.unwrap();
        assert_eq!(builds.len(), 1);
        assert_eq!(builds[0].id, "b1");
        assert_eq!(
            store.resolve_tag("py", "v2").await.unwrap().as_deref(),
            Some("sha256:a")
        );
    }

    #[tokio::test]
    async fn deleting_a_template_drops_its_tags_and_a_build_brings_it_back() {
        let store = Store::open_in_memory().await.unwrap();
        store.begin_build(&building("b1", "py", 1)).await.unwrap();
        store
            .finish_build("b1", "sha256:a", "{}", &["latest".to_string()], 2)
            .await
            .unwrap();
        assert!(store.delete_template("py", 3).await.unwrap());
        assert!(!store.delete_template("py", 4).await.unwrap());
        assert_eq!(store.resolve_tag("py", "latest").await.unwrap(), None);
        assert!(store.list_tags(Some("py")).await.unwrap().is_empty());
        store.begin_build(&building("b2", "py", 5)).await.unwrap();
        assert_eq!(store.list_templates().await.unwrap()[0].deleted_at_ms, 0);
    }

    #[tokio::test]
    async fn tags_are_pruned_to_the_newest_assignments() {
        let store = Store::open_in_memory().await.unwrap();
        for (n, digest) in ["sha256:1", "sha256:2", "sha256:3"].iter().enumerate() {
            store
                .put_ready_build(&BuildRow {
                    id: format!("b{n}"),
                    digest: digest.to_string(),
                    template: "py".into(),
                    created_at_ms: n as i64,
                    ..Default::default()
                })
                .await
                .unwrap();
            store
                .assign_tag("py", "latest", digest, n as i64)
                .await
                .unwrap();
            store
                .assign_tag("py", "v1", digest, n as i64)
                .await
                .unwrap();
        }
        assert_eq!(store.prune_tags(2, 9).await.unwrap(), 2);
        let kept: Vec<_> = store
            .list_tags(Some("py"))
            .await
            .unwrap()
            .into_iter()
            .filter(|t| t.tag == "latest")
            .map(|t| t.digest)
            .collect();
        assert_eq!(kept, ["sha256:2", "sha256:3"]);
        let untagged = |digest: &str| {
            let store = store.clone();
            let digest = digest.to_string();
            async move {
                store
                    .get_build(&digest)
                    .await
                    .unwrap()
                    .unwrap()
                    .untagged_at_ms
            }
        };
        assert_eq!(untagged("sha256:1").await, 9);
        assert_eq!(untagged("sha256:2").await, 0);
        assert_eq!(store.delete_tag("py", "latest", 10).await.unwrap(), 2);
        assert_eq!(untagged("sha256:2").await, 0, "v1 still names it");
        store.delete_template("py", 11).await.unwrap();
        assert_eq!(untagged("sha256:2").await, 11);
        store
            .assign_tag("py", "back", "sha256:2", 12)
            .await
            .unwrap();
        assert_eq!(untagged("sha256:2").await, 0);
    }

    #[tokio::test]
    async fn a_ready_build_put_twice_is_kept_once_and_revived_when_dropped() {
        let store = Store::open_in_memory().await.unwrap();
        let row = BuildRow {
            id: "b1".into(),
            digest: "sha256:a".into(),
            template: "py".into(),
            ..Default::default()
        };
        store.put_ready_build(&row).await.unwrap();
        store
            .put_ready_build(&BuildRow {
                id: "b2".into(),
                ..row.clone()
            })
            .await
            .unwrap();
        assert_eq!(store.list_builds(None).await.unwrap().len(), 1);
        store
            .drop_builds(std::slice::from_ref(&row.digest), 1)
            .await
            .unwrap();
        store.put_ready_build(&row).await.unwrap();
        assert_eq!(
            store.get_build("sha256:a").await.unwrap().unwrap().status,
            READY
        );
    }

    #[tokio::test]
    async fn stale_builds_fail_and_node_builds_are_replaced() {
        let store = Store::open_in_memory().await.unwrap();
        store.begin_build(&building("b1", "py", 1)).await.unwrap();
        store.begin_build(&building("b2", "py", 100)).await.unwrap();
        assert_eq!(store.fail_stale_builds(50, 200).await.unwrap(), 1);

        store
            .replace_node_builds("n1", &["sha256:a".into(), "sha256:b".into()], 1)
            .await
            .unwrap();
        store
            .replace_node_builds("n1", &["sha256:b".into()], 2)
            .await
            .unwrap();
        store
            .replace_node_builds("n2", &["sha256:a".into()], 2)
            .await
            .unwrap();
        assert_eq!(
            store.list_node_builds().await.unwrap(),
            vec![
                ("n1".to_string(), "sha256:b".to_string()),
                ("n2".to_string(), "sha256:a".to_string())
            ]
        );
    }
}
