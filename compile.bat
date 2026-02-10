cls

@REM powershell Get-ChildItem -Recurse -Filter *.obj | Remove-Item -Force

clang-cl /c ^
src/cell.cpp ^
src/circuit.cpp ^
src/circuit_node.cpp ^
src/circuit_node_crypto_state.cpp ^
src/consensus.cpp ^
src/hidden_service.cpp ^
src/onion_router.cpp ^
src/relay_cell.cpp ^
src/tor_socket.cpp ^
src/tor_stream.cpp ^
src/crypto/hybrid_encryption.cpp ^
src/crypto/key_agreement_ntor.cpp ^
src/crypto/key_agreement_tap.cpp ^
src/parsers/consensus_parser.cpp ^
src/parsers/hidden_service_descriptor_parser.cpp ^
src/parsers/introduction_point_parser.cpp ^
src/parsers/onion_router_descriptor_parser.cpp


@REM lib.exe ^
@REM /OUT minitor.lib ^
@REM /MT ^
@REM /O1 ^
@REM src/cell.o ^
@REM src/circuit.o ^
@REM src/circuit_node.o ^
@REM src/circuit_node_crypto_state.o ^
@REM src/consensus.o ^
@REM src/hidden_service.o ^
@REM src/onion_router.o ^
@REM src/relay_cell.o ^
@REM src/tor_socket.o ^
@REM src/tor_stream.o ^
@REM src/crypto/hybrid_encryption.o ^
@REM src/crypto/key_agreement_ntor.o ^
@REM src/crypto/key_agreement_tap.o ^
@REM src/parsers/consensus_parser.o ^
@REM src/parsers/hidden_service_descriptor_parser.o ^
@REM src/parsers/introduction_point_parser.o ^
@REM src/parsers/onion_router_descriptor_parser.o