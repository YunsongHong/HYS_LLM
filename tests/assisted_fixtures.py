"""Small synthetic inputs shared by assisted-workbench regression tests."""

import base64
from io import BytesIO
import uuid

from PIL import Image

from paramguard.assisted_input import parse_page_tsv


def png(color="white", size=(700, 400)):
    stream = BytesIO()
    Image.new("RGB", size, color).save(stream, format="PNG")
    return stream.getvalue()


def tsv(rows):
    lines = [
        "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext"
    ]
    for i, (key, value) in enumerate(rows):
        for w, text in enumerate([key, *value.split(" ")]):
            lines.append(
                f"5\t1\t1\t1\t{i+1}\t{w+1}\t{10+w*150}\t{10+i*30}\t100\t20\t95\t{text}"
            )
    return "\n".join(lines) + "\n"


class Reader:
    def __init__(self, left=None, right=None):
        self.calls = 0
        self.left = [("P1", "1.20 bar")] if left is None else left
        self.right = self.left if right is None else right

    def version(self):
        return "SYNTHETIC-TEST-READER-1; not real OCR"

    def __call__(self, image, width, height):
        rows = self.left if self.calls % 2 == 0 else self.right
        self.calls += 1
        return parse_page_tsv(tsv(rows), width, height)


def create(workspace, targets="P1", **changes):
    return workspace.create(
        {
            "label": "SYNTHETIC TEST",
            "targets": targets,
            "acknowledge_assisted": True,
            "confirm_local_test_data": True,
            "confirm_single_column": True,
            "command_id": uuid.uuid4().hex,
            **changes,
        }
    )


def binding(workspace, job, **changes):
    state = workspace.state(job)
    return {
        "expected_revision": state["revision"],
        "manifest_hash": state["manifest_hash"],
        "command_id": uuid.uuid4().hex,
        **changes,
    }


def upload(workspace, job, side, data=None, **changes):
    return workspace.upload(
        job,
        binding(
            workspace,
            job,
            side=side,
            name="synthetic.png",
            data=base64.b64encode(png() if data is None else data).decode(),
            **changes,
        ),
    )


def ready(workspace, targets="P1", size=(700, 400)):
    job = create(workspace, targets)["job_id"]
    upload(workspace, job, "left", png(size=size))
    upload(workspace, job, "right", png("#fafafa", size=size))
    workspace.start(job, binding(workspace, job))
    if not workspace.wait(10):
        raise AssertionError("test OCR worker failed to stop")
    if workspace.state(job)["state"] != "READY":
        raise AssertionError(workspace.state(job))
    return job
