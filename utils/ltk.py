from typing import Literal

__all__ = ["ltk"]

class Ltk:
    """
    Literal types for Tkinter constants because type checking YAY
    """
    NO = FALSE = OFF = 0
    YES = TRUE = ON = 1
    
    # -anchor and -sticky
    N: Literal['n'] = 'n'
    S: Literal['s'] = 's'
    W: Literal['w'] = 'w'
    E: Literal['e'] = 'e'
    NW: Literal['nw'] = 'nw'
    SW: Literal['sw'] = 'sw'
    NE: Literal['ne'] = 'ne'
    SE: Literal['se'] = 'se'
    NS: Literal['ns'] = 'ns'
    EW: Literal['ew'] = 'ew'
    NSEW: Literal['nsew'] = 'nsew'
    CENTER: Literal['center'] = 'center'
    
    # -fill
    NONE: Literal['none'] = 'none'
    X: Literal['x'] = 'x'
    Y: Literal['y'] = 'y'
    BOTH: Literal['both'] = 'both'
    
    # -side
    LEFT: Literal['left'] = 'left'
    TOP: Literal['top'] = 'top'
    RIGHT: Literal['right'] = 'right'
    BOTTOM: Literal['bottom'] = 'bottom'
    
    # -relief
    RAISED: Literal['raised'] = 'raised'
    SUNKEN: Literal['sunken'] = 'sunken'
    FLAT: Literal['flat'] = 'flat'
    RIDGE: Literal['ridge'] = 'ridge'
    GROOVE: Literal['groove'] = 'groove'
    SOLID: Literal['solid'] = 'solid'
    
    # -orient
    HORIZONTAL: Literal['horizontal'] = 'horizontal'
    VERTICAL: Literal['vertical'] = 'vertical'
    
    # -tabs
    NUMERIC: Literal['numeric'] = 'numeric'
    
    # -wrap
    CHAR: Literal['char'] = 'char'
    WORD: Literal['word'] = 'word'
    
    # -align
    BASELINE: Literal['baseline'] = 'baseline'
    
    # -bordermode
    INSIDE: Literal['inside'] = 'inside'
    OUTSIDE: Literal['outside'] = 'outside'
    
    # Special tags, marks and insert positions
    SEL: Literal['sel'] = 'sel'
    SEL_FIRST: Literal['sel.first'] = 'sel.first'
    SEL_LAST: Literal['sel.last'] = 'sel.last'
    END: Literal['end'] = 'end'
    INSERT: Literal['insert'] = 'insert'
    CURRENT: Literal['current'] = 'current'
    ANCHOR: Literal['anchor'] = 'anchor'
    ALL: Literal['all'] = 'all'  # e.g. Canvas.delete(ALL)
    
    # Text widget and button states
    NORMAL: Literal['normal'] = 'normal'
    DISABLED: Literal['disabled'] = 'disabled'
    ACTIVE: Literal['active'] = 'active'
    # Canvas state
    HIDDEN: Literal['hidden'] = 'hidden'
    
    # Menu item types
    CASCADE: Literal['cascade'] = 'cascade'
    CHECKBUTTON: Literal['checkbutton'] = 'checkbutton'
    COMMAND: Literal['command'] = 'command'
    RADIOBUTTON: Literal['radiobutton'] = 'radiobutton'
    SEPARATOR: Literal['separator'] = 'separator'
    
    # Selection modes for list boxes
    SINGLE: Literal['single'] = 'single'
    BROWSE: Literal['browse'] = 'browse'
    MULTIPLE: Literal['multiple'] = 'multiple'
    EXTENDED: Literal['extended'] = 'extended'
    
    # Activestyle for list boxes
    # NONE='none' is also valid
    DOTBOX: Literal['dotbox'] = 'dotbox'
    UNDERLINE: Literal['underline'] = 'underline'
    
    # Various canvas styles
    PIESLICE: Literal['pieslice'] = 'pieslice'
    CHORD: Literal['chord'] = 'chord'
    ARC: Literal['arc'] = 'arc'
    FIRST: Literal['first'] = 'first'
    LAST: Literal['last'] = 'last'
    BUTT: Literal['butt'] = 'butt'
    PROJECTING: Literal['projecting'] = 'projecting'
    ROUND: Literal['round'] = 'round'
    BEVEL: Literal['bevel'] = 'bevel'
    MITER: Literal['miter'] = 'miter'
    
    # Arguments to xview/yview
    MOVETO: Literal['moveto'] = 'moveto'
    SCROLL: Literal['scroll'] = 'scroll'
    UNITS: Literal['units'] = 'units'
    PAGES: Literal['pages'] = 'pages'


ltk: Ltk = Ltk()
