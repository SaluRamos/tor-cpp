cls

powershell Get-ChildItem -Recurse -Filter *.obj | Remove-Item -Force

clang-cl /c ^
cell.cpp ^
circuit.cpp ^
circuit_node.cpp ^
circuit_node_crypto_state.cpp ^
consensus.cpp ^
hidden_service.cpp ^
onion_router.cpp ^
relay_cell.cpp ^
tor_socket.cpp ^
tor_stream.cpp ^
crypto\hybrid_encryption.cpp ^
crypto\key_agreement_ntor.cpp ^
crypto\key_agreement_tap.cpp ^
parsers\consensus_parser.cpp ^
parsers\hidden_service_descriptor_parser.cpp ^
parsers\introduction_point_parser.cpp ^
parsers\onion_router_descriptor_parser.cpp


@REM lib.exe ^
@REM /OUT minitor.lib ^
@REM /MT ^
@REM /O1 ^
@REM cell.o ^
@REM circuit.o ^
@REM circuit_node.o ^
@REM circuit_node_crypto_state.o ^
@REM consensus.o ^
@REM hidden_service.o ^
@REM onion_router.o ^
@REM relay_cell.o ^
@REM tor_socket.o ^
@REM tor_stream.o ^
@REM crypto\hybrid_encryption.o ^
@REM crypto\key_agreement_ntor.o ^
@REM crypto\key_agreement_tap.o ^
@REM parsers\consensus_parser.o ^
@REM parsers\hidden_service_descriptor_parser.o ^
@REM parsers\introduction_point_parser.o ^
@REM parsers\onion_router_descriptor_parser.o