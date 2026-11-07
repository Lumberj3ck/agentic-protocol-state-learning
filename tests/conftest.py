import pytest

from smlearn import testbed

SSH_TARGETS = ["openssh", "dropbear", "asyncssh"]


@pytest.fixture(scope="session", params=SSH_TARGETS)
def ssh_instance(request):
    target = testbed.load_target(request.param)
    testbed.build(target)
    inst = testbed.start(target)
    yield inst
    inst.stop()
