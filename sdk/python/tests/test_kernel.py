"""A template's kernel, as a build names it and as records report it."""

from burrow import KernelCapabilities, KernelInfo, TemplateBuilder
from burrow._pb import api_pb2, common_pb2
from burrow._wire import kernel
from burrow.sandbox import _to_sandbox_info
from burrow.template import build_template, to_template_info

KERNEL = common_pb2.Kernel(
    name="ch-linux",
    digest="ab" * 32,
    version="7.2.8+",
    arch="x86_64",
    capabilities=common_pb2.KernelCapabilities(
        is_kvm_built_in=True,
        is_virtio_mem_built_in=True,
        is_vsock_built_in=True,
        is_virtio_blk_built_in=True,
        is_ext4_built_in=True,
    ),
    detected_from="strings",
)

PARSED = KernelInfo(
    name="ch-linux",
    digest="ab" * 32,
    version="7.2.8+",
    arch="x86_64",
    capabilities=KernelCapabilities(kvm=True, virtio_mem=True, vsock=True, virtio_blk=True, ext4=True),
    detected_from="strings",
)


class Streams:
    def __init__(self):
        self.requests = []

    def server_stream(self, method, request, timeout):
        self.requests.append(request)
        yield api_pb2.BuildLog(done=api_pb2.BuildDone(template="t"))


def test_a_build_names_its_kernel_and_leaves_it_to_the_node_when_it_does_not():
    transport = Streams()
    template = TemplateBuilder().from_image("alpine:3.20")
    build_template(transport, template, "t", kernel="ch-linux")
    build_template(transport, template, "t")
    assert [r.kernel for r in transport.requests] == ["ch-linux", ""]


def test_a_template_and_a_sandbox_report_the_kernel_they_boot():
    assert to_template_info(api_pb2.TemplateInfo(name="t", kernel=KERNEL)).kernel == PARSED
    assert to_template_info(api_pb2.TemplateInfo(name="t")).kernel is None
    assert _to_sandbox_info(common_pb2.Sandbox(id="s", kernel=KERNEL)).kernel == PARSED


def test_a_boot_takes_the_templates_current_kernel_unless_told_to_keep_its_own(transport, sandbox):
    calls = []

    def unary(method, request, timeout=None):
        calls.append((method, request))
        return common_pb2.Sandbox(id="sbx_test", state=common_pb2.SANDBOX_STATE_RUNNING)

    transport.unary = unary
    sandbox.start()
    sandbox.start(keep_kernel=True)
    assert [(m, r.sandbox_id, r.is_kernel_kept) for m, r in calls] == [
        ("StartSandbox", "sbx_test", False),
        ("StartSandbox", "sbx_test", True),
    ]


def test_a_node_kernel_says_which_hypervisors_it_is_the_default_for():
    node_kernel = common_pb2.Kernel()
    node_kernel.CopyFrom(KERNEL)
    node_kernel.hypervisors.append("cloud-hypervisor")
    node_kernel.default_for.append("cloud-hypervisor")
    assert kernel(node_kernel) == KernelInfo(
        **{**PARSED.__dict__, "hypervisors": ["cloud-hypervisor"], "default_for": ["cloud-hypervisor"]}
    )
