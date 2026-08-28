"""Frozen synthetic development, hidden-test, and challenge case definitions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json

from .evaluation import DatasetSplit
from .synthetic import (
    SyntheticCaseSpec,
    SyntheticDegradation,
    SyntheticValuePair,
)


class ChallengeCategory(str, Enum):
    CLEAN = "CLEAN"
    NEGATIVE_SIGN = "NEGATIVE_SIGN"
    DECIMAL_PRECISION = "DECIMAL_PRECISION"
    LEADING_ZERO = "LEADING_ZERO"
    UNIT = "UNIT"
    TEXT_MODE = "TEXT_MODE"
    MISSING_FIELD = "MISSING_FIELD"
    LOW_CONTRAST = "LOW_CONTRAST"
    BLUR = "BLUR"


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    spec: SyntheticCaseSpec
    split: DatasetSplit
    categories: tuple[ChallengeCategory, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.spec, SyntheticCaseSpec):
            raise TypeError("spec must be a SyntheticCaseSpec")
        if not isinstance(self.split, DatasetSplit):
            raise TypeError("split must be a DatasetSplit")
        if not isinstance(self.categories, tuple) or not self.categories:
            raise ValueError("categories must be a non-empty tuple")
        if any(
            not isinstance(category, ChallengeCategory)
            for category in self.categories
        ):
            raise TypeError("categories must contain ChallengeCategory values")
        if len(set(self.categories)) != len(self.categories):
            raise ValueError("categories must not contain duplicates")

    def to_record(self) -> dict[str, object]:
        return {
            "case_id": self.spec.case_id,
            "split": self.split.value,
            "categories": [item.value for item in self.categories],
            "left_degradation": self.spec.left_degradation.value,
            "right_degradation": self.spec.right_degradation.value,
            "values": [
                {
                    "parameter_id": item.parameter_id,
                    "left_raw": item.left_raw,
                    "right_raw": item.right_raw,
                }
                for item in self.spec.values
            ],
        }


@dataclass(frozen=True, slots=True)
class SyntheticBenchmark:
    benchmark_id: str
    version: str
    cases: tuple[BenchmarkCase, ...]

    def __post_init__(self) -> None:
        for name in ("benchmark_id", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or value.strip() == "":
                raise ValueError(f"{name} must be non-empty text")
        if not isinstance(self.cases, tuple) or not self.cases:
            raise ValueError("cases must be a non-empty tuple")
        if any(not isinstance(item, BenchmarkCase) for item in self.cases):
            raise TypeError("cases must contain BenchmarkCase values")
        case_ids = tuple(item.spec.case_id for item in self.cases)
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("benchmark case IDs must not contain duplicates")
        required_splits = {
            DatasetSplit.DEVELOPMENT,
            DatasetSplit.HIDDEN_TEST,
            DatasetSplit.CHALLENGE,
        }
        if {item.split for item in self.cases} != required_splits:
            raise ValueError("benchmark must contain development, hidden, and challenge cases")

    def cases_for(self, split: DatasetSplit) -> tuple[BenchmarkCase, ...]:
        if not isinstance(split, DatasetSplit):
            raise TypeError("split must be a DatasetSplit")
        return tuple(item for item in self.cases if item.split is split)

    def to_record(self) -> dict[str, object]:
        return {
            "benchmark_schema_version": 1,
            "benchmark_id": self.benchmark_id,
            "version": self.version,
            "cases": [item.to_record() for item in self.cases],
        }

    @property
    def content_sha256(self) -> str:
        encoded = json.dumps(
            self.to_record(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def _values(
    *,
    temperature: tuple[str | None, str | None] = ("37.0 C", "37.0 C"),
    pressure: tuple[str | None, str | None] = ("1.20 bar", "1.20 bar"),
    speed: tuple[str | None, str | None] = ("0800 rpm", "0800 rpm"),
    mode: tuple[str | None, str | None] = ("AUTO", "AUTO"),
) -> tuple[SyntheticValuePair, ...]:
    return (
        SyntheticValuePair("temperature", *temperature),
        SyntheticValuePair("pressure", *pressure),
        SyntheticValuePair("speed", *speed),
        SyntheticValuePair("mode", *mode),
    )


SYNTHETIC_BENCHMARK_V1 = SyntheticBenchmark(
    benchmark_id="paramguard-synthetic-benchmark",
    version="1.0",
    cases=(
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="dev-mixed-001",
                values=_values(
                    pressure=("1.20 bar", "1.25 bar"),
                    speed=("0800 rpm", "800 rpm"),
                ),
            ),
            split=DatasetSplit.DEVELOPMENT,
            categories=(ChallengeCategory.CLEAN,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(case_id="hidden-all-same", values=_values()),
            split=DatasetSplit.HIDDEN_TEST,
            categories=(ChallengeCategory.CLEAN,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="hidden-negative-sign",
                values=_values(temperature=("-5.0 C", "5.0 C")),
            ),
            split=DatasetSplit.HIDDEN_TEST,
            categories=(ChallengeCategory.NEGATIVE_SIGN,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="hidden-decimal-precision",
                values=_values(pressure=("1.20 bar", "1.2 bar")),
            ),
            split=DatasetSplit.HIDDEN_TEST,
            categories=(ChallengeCategory.DECIMAL_PRECISION,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="hidden-leading-zero",
                values=_values(speed=("0800 rpm", "800 rpm")),
            ),
            split=DatasetSplit.HIDDEN_TEST,
            categories=(ChallengeCategory.LEADING_ZERO,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="hidden-unit-change",
                values=_values(pressure=("1.0 bar", "1.0 psi")),
            ),
            split=DatasetSplit.HIDDEN_TEST,
            categories=(ChallengeCategory.UNIT,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="hidden-mode-change",
                values=_values(mode=("AUTO", "MANUAL")),
            ),
            split=DatasetSplit.HIDDEN_TEST,
            categories=(ChallengeCategory.TEXT_MODE,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="hidden-missing-left",
                values=_values(temperature=(None, "37.0 C")),
            ),
            split=DatasetSplit.HIDDEN_TEST,
            categories=(ChallengeCategory.MISSING_FIELD,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="challenge-low-contrast",
                values=_values(pressure=("1.20 bar", "1.25 bar")),
                left_degradation=SyntheticDegradation.LOW_CONTRAST,
            ),
            split=DatasetSplit.CHALLENGE,
            categories=(ChallengeCategory.LOW_CONTRAST,),
        ),
        BenchmarkCase(
            spec=SyntheticCaseSpec(
                case_id="challenge-blur",
                values=_values(speed=("0800 rpm", "800 rpm")),
                left_degradation=SyntheticDegradation.BLUR,
            ),
            split=DatasetSplit.CHALLENGE,
            categories=(ChallengeCategory.BLUR,),
        ),
    ),
)
