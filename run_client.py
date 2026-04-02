import importlib
from pathlib import Path

from config.config import ConfigHandler
ConfigHandler()  # ensure config.json exists and is valid on startup

from new_client import SecureChatClient

if __name__ == "__main__":
    UI_folder: Path = Path(__file__).parent / "UIs"
    UIs: list[Path] = [file for file in UI_folder.glob("*.py")]
    print('Pick a UI: ', end='\n')
    for i, ui in enumerate(UIs, start=1):
        print(f"{i}: {ui.stem}")
    
    valid: bool = False
    while not valid:
        try:
            ui_index: int = int(input('Pick the UI to use (1-' + str(len(UIs)) + '): '))
            if 1 <= ui_index <= len(UIs):
                valid = True
            else:
                int('e')
        except ValueError:
            print("Invalid input. Please enter a number between 1 and", len(UIs))
    
    ui_path: Path = UIs[ui_index - 1]
    print(f"Running {ui_path.stem}...")
    iu_module = importlib.import_module(f"UIs.{ui_path.stem}")
    try:
        iu_module.run(SecureChatClient)
    except AttributeError:
        print("No run() function found in the selected UI.")
    