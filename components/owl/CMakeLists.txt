idf_component_register(
SRCS 
# port
../../port/impl.c
# original
../../src/state.c
../../src/peers.c
../../src/channel.c
../../src/sync.c
../../src/election.c
../../src/version.c
../../src/hashmap.c
../../src/rx.c
../../src/tx.c
../../src/wire.c
../../src/log.c
../../src/siphash24.c
../../src/crc32.c
../../src/frame.c
../../src/schedule.c
INCLUDE_DIRS ../../port
PRIV_INCLUDE_DIRS ../../port/fakesys
)
