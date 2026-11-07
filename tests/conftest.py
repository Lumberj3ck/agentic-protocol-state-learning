import pytest

from smlearn import testbed

import os

# SMLEARN_TARGETS=paramiko,golang runs the mapper tests against other targets/<name>.
SSH_TARGETS = os.environ.get("SMLEARN_TARGETS", "openssh,dropbear,asyncssh").split(",")


@pytest.fixture(scope="session", params=SSH_TARGETS)
def ssh_instance(request):
    target = testbed.load_target(request.param)
    testbed.build(target)
    inst = testbed.start(target)
    yield inst
    inst.stop()
