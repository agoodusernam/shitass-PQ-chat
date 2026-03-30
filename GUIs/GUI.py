from typing import Literal

from ui_base import UIBase

class Ltk:
    """
    Literal types for Tkinter constants because type checking YAY
    """
    END: Literal["end"] = "end"
    W: Literal["w"] = "w"
    X: Literal["x"] = "x"
    Y: Literal["y"] = "y"
    BOTH: Literal["both"] = "both"
    RIGHT: Literal["right"] = "right"
    LEFT: Literal["left"] = "left"
    DISABLED: Literal["disabled"] = "disabled"
    NORMAL: Literal["normal"] = "normal"
    ACTIVE: Literal["active"] = "active"
    FLAT: Literal["flat"] = "flat"
    HORIZONTAL: Literal["horizontal"] = "horizontal"
    VERTICAL: Literal["vertical"] = "vertical"
    WORD: Literal["word"] = "word"
    NONE: Literal["none"] = "none"


ltk: Ltk = Ltk()

class GUI(UIBase):
    def __init__(self):
        pass