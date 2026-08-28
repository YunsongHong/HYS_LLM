"""参数值的确定性比较。

这里故意不调用 LLM。只要输入相同，这段代码就会稳定地产生相同结果，
因此它更适合承担“是否完全一致”的关键判断。
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
import re
import unicodedata


class ComparisonKind(str, Enum):
    """比较结果的类别。"""

    EXACT_MATCH = "EXACT_MATCH"
    MISSING_VALUE = "MISSING_VALUE"
    FORMAT_DIFFERENCE = "FORMAT_DIFFERENCE"
    VALUE_MISMATCH = "VALUE_MISMATCH"
    UNIT_MISMATCH = "UNIT_MISMATCH"
    VALUE_AND_UNIT_MISMATCH = "VALUE_AND_UNIT_MISMATCH"
    UNPARSEABLE_DIFFERENCE = "UNPARSEABLE_DIFFERENCE"
    NORMALIZATION_COLLISION = "NORMALIZATION_COLLISION"
    TEXT_MISMATCH = "TEXT_MISMATCH"


@dataclass(frozen=True)
class ParsedNumber:
    """为了说明差异而解析出的十进制数和单位。"""

    number: Decimal
    unit: str


@dataclass(frozen=True)
class ComparisonResult:
    """一次比较的完整、不可变结果。"""

    left_raw: str | None
    right_raw: str | None
    exact_match: bool
    kind: ComparisonKind
    explanation: str
    left_number: Decimal | None = None
    right_number: Decimal | None = None
    left_unit: str | None = None
    right_unit: str | None = None


_NUMBER_AND_UNIT = re.compile(
    r"^\s*"
    r"([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)"
    r"(?:\s*([A-Za-zµμ°%][A-Za-z0-9µμ°%/·*^()_-]*))?"
    r"\s*$"
)

_STARTS_LIKE_NUMBER = re.compile(r"^\s*[+\-−]?(?:\d|\.)")


def _is_missing(value: str | None) -> bool:
    """None、空字符串和纯空白都表示没有可核验的值。"""

    return value is None or value.strip() == ""


def _validate_input_type(name: str, value: str | None) -> None:
    """尽早给出清晰的输入错误，而不是模糊的 AttributeError。"""

    if value is not None and type(value) is not str:
        raise TypeError(
            f"{name} must be str or None, got {type(value).__name__}. "
            "Display values must stay as strings so leading zeros and precision are preserved."
        )


def _parse_number_and_unit(value: str) -> ParsedNumber | None:
    """尝试把文本拆成十进制数和单位；失败时返回 None。"""

    match = _NUMBER_AND_UNIT.fullmatch(value)
    if match is None:
        return None

    try:
        number = Decimal(match.group(1))
    except InvalidOperation:
        return None

    return ParsedNumber(number=number, unit=match.group(2) or "")


def _normalise_for_explanation(value: str) -> str:
    """只用于解释潜在格式差异，绝不用于最终放行。"""

    unicode_normalised = unicodedata.normalize("NFKC", value)
    collapsed_spaces = " ".join(unicode_normalised.split())
    return collapsed_spaces.casefold()


def compare_values(left: str | None, right: str | None) -> ComparisonResult:
    """严格比较两个参数值。

    业务规则：只有两个非空原始字符串逐字符相同，`exact_match` 才是 True。
    数值解析和文本标准化只用来解释为什么不同，不能改变最终结论。
    """

    _validate_input_type("left", left)
    _validate_input_type("right", right)

    if _is_missing(left) or _is_missing(right):
        return ComparisonResult(
            left_raw=left,
            right_raw=right,
            exact_match=False,
            kind=ComparisonKind.MISSING_VALUE,
            explanation="至少一侧缺少可核验值，不能判定为完全一致。",
        )

    # 经过缺失检查后，类型检查器仍不知道它们一定是字符串。
    assert left is not None and right is not None

    if left == right:
        return ComparisonResult(
            left_raw=left,
            right_raw=right,
            exact_match=True,
            kind=ComparisonKind.EXACT_MATCH,
            explanation="两个非空原始字符串逐字符完全一致。",
        )

    left_parsed = _parse_number_and_unit(left)
    right_parsed = _parse_number_and_unit(right)

    if left_parsed is not None and right_parsed is not None:
        # 单位可能区分大小写，因此这里不使用 casefold 或 Unicode 兼容归一化。
        same_unit_for_explanation = left_parsed.unit == right_parsed.unit
        same_number = left_parsed.number == right_parsed.number

        common = {
            "left_raw": left,
            "right_raw": right,
            "exact_match": False,
            "left_number": left_parsed.number,
            "right_number": right_parsed.number,
            "left_unit": left_parsed.unit,
            "right_unit": right_parsed.unit,
        }

        if not same_unit_for_explanation and not same_number:
            return ComparisonResult(
                **common,
                kind=ComparisonKind.VALUE_AND_UNIT_MISMATCH,
                explanation="十进制数值和单位都不同；必须升级复核。",
            )

        if not same_unit_for_explanation:
            return ComparisonResult(
                **common,
                kind=ComparisonKind.UNIT_MISMATCH,
                explanation="数值可以解析，但单位不同；必须升级复核。",
            )

        if not same_number:
            return ComparisonResult(
                **common,
                kind=ComparisonKind.VALUE_MISMATCH,
                explanation="单位相同，但十进制数值不同。",
            )

        return ComparisonResult(
            **common,
            kind=ComparisonKind.FORMAT_DIFFERENCE,
            explanation=("解析后的数值和单位相同，但原始显示不同；" "因为要求完全一致，所以仍不能自动通过。"),
        )

    if _normalise_for_explanation(left) == _normalise_for_explanation(right):
        return ComparisonResult(
            left_raw=left,
            right_raw=right,
            exact_match=False,
            kind=ComparisonKind.NORMALIZATION_COLLISION,
            explanation=("宽松标准化后文本发生碰撞，但原始文本不同；" "这种变换可能改变业务含义，必须按普通差异复核。"),
        )

    left_starts_like_number = _STARTS_LIKE_NUMBER.match(left) is not None
    right_starts_like_number = _STARTS_LIKE_NUMBER.match(right) is not None
    if left_starts_like_number or right_starts_like_number:
        return ComparisonResult(
            left_raw=left,
            right_raw=right,
            exact_match=False,
            kind=ComparisonKind.UNPARSEABLE_DIFFERENCE,
            explanation=("至少一侧看起来像数值，但不符合当前安全解析格式；" "程序不会猜测千位符、非法小数点或未知单位。"),
        )

    return ComparisonResult(
        left_raw=left,
        right_raw=right,
        exact_match=False,
        kind=ComparisonKind.TEXT_MISMATCH,
        explanation="原始文本不同，且不能解释为单纯的数值或格式差异。",
    )
