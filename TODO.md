## TODOs, no specific ordering, just the order I happen to think of them
### Fixes/refactors:
1.
   1. The error stuff is still scuffed
        - Swallowing exceptions silently
   2. Duplicated code
   3. Class ownership structure for the client/protocol needs to be redone completely
   4. Fat ABCs
   5. Many overly large functions and classes
        - server.py is the worst one
        - High cyclomatic complexity (>8): `UIs/TUI.py:222 chat_loop()` CC=32, `new_client.py:416 route()` CC=23, `new_client.py:565 handle_message_types()` CC=20, `client/deaddrop_manager.py:717 _process_data_streaming()` CC=19, `client/key_exchange_manager.py:183 handle_rekey()` CC=14
        - >5 positional params: `speed_test.py:137 run_benchmark()` (8), `protocol/create_messages.py:72 create_ke_mlkem_ct_keys()` (6)
   6. Continue deslopifying
   7. Server identifier should be in config
   8. Debug GUI and TUI very out of date

### Tests:
2.
   1. Write tests for managers
   2. Untested paths: socket connect errors, rekey race-condition winner logic (`client_random` compare), sender-thread lifecycle, deaddrop upload-accept timeout, rate-limit window boundary

### Non Code:
3.
   1. File structure needs to be redone, goes with 1.iii.
   2. Setup pylint
   3. Do some CI/CD for automated tests and formatting
   4. Separate testing and fuzzing

### Features:
4.
   1. Encoding (Opus?) for voice calls
      - Would require an extra lib that can encode/decode in real time
   2. Bandwidth limits for file transfers
   3. Voice messages