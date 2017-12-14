#ifndef arm64_state_h
#define arm64_state_h

/*
 * GPR context
 */

struct arm_saved_state32 {
  uint32_t  r[13];    /* General purpose register r0-r12 */
  uint32_t  sp;      /* Stack pointer r13 */
  uint32_t  lr;      /* Link register r14 */
  uint32_t  pc;      /* Program counter r15 */
  uint32_t  cpsr;    /* Current program status register */
  uint32_t  far;    /* Virtual fault address */
  uint32_t  esr;    /* Exception syndrome register */
  uint32_t  exception;  /* Exception number */
};
typedef struct arm_saved_state32 arm_saved_state32_t;

struct arm_saved_state32_tagged {
  uint32_t          tag;
  struct arm_saved_state32  state;
};
typedef struct arm_saved_state32_tagged arm_saved_state32_tagged_t;

#define ARM_SAVED_STATE32_COUNT ((mach_msg_type_number_t) \
(sizeof (arm_saved_state32_t)/sizeof(unsigned int)))

struct arm_saved_state64 {
  uint64_t    x[29];    /* General purpose registers x0-x28 */
  uint64_t    fp;      /* Frame pointer x29 */
  uint64_t    lr;      /* Link register x30 */
  uint64_t    sp;      /* Stack pointer x31 */
  uint64_t    pc;      /* Program counter */
  uint32_t    cpsr;    /* Current program status register */
  uint32_t  reserved;  /* Reserved padding */
  uint64_t  far;    /* Virtual fault address */
  uint32_t  esr;    /* Exception syndrome register */
  uint32_t  exception;  /* Exception number */
};
typedef struct arm_saved_state64 arm_saved_state64_t;

#define ARM_SAVED_STATE64_COUNT ((mach_msg_type_number_t) \
(sizeof (arm_saved_state64_t)/sizeof(unsigned int)))

struct arm_saved_state {
	arm_state_hdr_t ash;
  union {
    struct arm_saved_state32 ss_32;
    struct arm_saved_state64 ss_64;
  } uss;
} __attribute__((aligned(16)));
#define  ss_32  uss.ss_32
#define  ss_64  uss.ss_64

typedef struct arm_saved_state arm_saved_state_t;

/*
 * NEON context
 */
typedef __uint128_t uint128_t;
typedef uint64_t uint64x2_t __attribute__((ext_vector_type(2)));
typedef uint32_t uint32x4_t __attribute__((ext_vector_type(4)));

struct arm_neon_saved_state32 {
  union {
    uint128_t  q[16];
    uint64_t  d[32];
    uint32_t  s[32];
  } v;
  uint32_t    fpsr;
  uint32_t    fpcr;
};
typedef struct arm_neon_saved_state32 arm_neon_saved_state32_t;

#define ARM_NEON_SAVED_STATE32_COUNT ((mach_msg_type_number_t) \
(sizeof (arm_neon_saved_state32_t)/sizeof(unsigned int)))

struct arm_neon_saved_state64 {
  union {
    uint128_t    q[32];
    uint64x2_t    d[32];
    uint32x4_t    s[32];
  } v;
  uint32_t    fpsr;
  uint32_t    fpcr;
};
typedef struct arm_neon_saved_state64 arm_neon_saved_state64_t;

#define ARM_NEON_SAVED_STATE64_COUNT ((mach_msg_type_number_t) \
(sizeof (arm_neon_saved_state64_t)/sizeof(unsigned int)))

struct arm_neon_saved_state {
	arm_state_hdr_t nsh;
  union {
    struct arm_neon_saved_state32 ns_32;
    struct arm_neon_saved_state64 ns_64;
  } uns;
};
typedef struct arm_neon_saved_state arm_neon_saved_state_t;
#define  ns_32  uns.ns_32
#define  ns_64  uns.ns_64

struct arm_context {
  struct arm_saved_state ss;
  struct arm_neon_saved_state ns;
};
typedef struct arm_context arm_context_t;

#define ARM_SAVED_STATE64 0x15

#define ARM_DEBUG_STATE64 15
const uint64_t ACT_DEBUGDATA_OFFSET = 0x438;

struct arm64_debug_state
{
  __uint64_t  bvr[16];
  __uint64_t  bcr[16];
  __uint64_t  wvr[16];
  __uint64_t  wcr[16];
  __uint64_t  mdscr_el1; /* Bit 0 is SS (Hardware Single Step) */
};

struct arm_debug_aggregate_state {
	arm_state_hdr_t          dsh;
  struct arm64_debug_state ds64;
} __attribute__((aligned(16)));



#endif
