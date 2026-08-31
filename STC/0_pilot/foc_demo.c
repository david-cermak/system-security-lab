//https://godbolt.org/z/jdMMEfbnG

/* ----------------------------------------------------------------------------
 * foc_demo.c - closed-loop field-oriented current control of a 3-phase PMSM,
 *              built on STC containers.
 *
 * Compile against this repo:   gcc -std=c11 -O2 -I include foc_demo.c -lm -o foc_demo
 * Run in Godbolt:              paste as C (gcc); add include path
 *                              https://raw.githubusercontent.com/stclib/stcsingle/main
 *                              (or include the single headers directly by URL).
 *                              Add -DDSP_TRIG_IMPL=2 to use the table-based
 *                              DSP trig and drop the -lm requirement.
 *
 * What it shows:
 *   1. A real closed loop: the PI voltage commands drive an electrical plant
 *      (R, Ld, Lq, back-EMF), and iq converges to iq_ref.
 *   2. The measured "phase currents" are a balanced 3-phase set (ia+ib+ic = 0)
 *      reconstructed from the true dq state, so the Clarke/Park transform has
 *      a valid operating point.
 *   3. An ADC glitch on phase b is rejected by a sliding median filter that is
 *      (a) computed on the newest samples, (b) done in the dq frame where the
 *      signals are DC in steady state, and (c) allocation-free: the window is
 *      an inplace STC stack and the sort runs on a local 5-float array.
 *
 * Containers used:
 *   stack   inplace (fixed capacity 5) sliding window for the dq medians -
 *           the only container in the 10 kHz control path. Zero heap.
 *   vec     host-side logging of the run (control path is heap-free).
 *   cbits   PWM switching-vector history (space-vector modulation).
 *   c_each, c_range, c_filter loop abstractions.
 * -------------------------------------------------------------------------- */
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

/* =====================================================================
 * dsp_math: portable sin/cos/sqrt for DSP/control loops.
 *
 *   DSP_TRIG_IMPL = 0  math.h            - host / Godbolt default (auto
 *                                          selected on x86 hosts).
 *   DSP_TRIG_IMPL = 1  CMSIS-DSP         - ARM DSP intrinsics
 *                                          arm_sin_f32/arm_cos_f32/
 *                                          arm_sqrt_f32 (auto-selected when
 *                                          <arm_math.h> defines ARM_MATH_CMx
 *                                          in a real Cortex-M project).
 *                                          Table-based, deterministic.
 *   DSP_TRIG_IMPL = 2  built-in          - self-contained 128-entry sine
 *                                          LUT + linear interpolation and a
 *                                          Quake-style fast inverse sqrt:
 *                                          no libm and no DSP library at
 *                                          all. Runs on FPU-less MCUs and
 *                                          in Godbolt: build with
 *                                          -DDSP_TRIG_IMPL=2.
 *
 * Note: GCC/Clang do NOT lower __builtin_sinf/cosf to hardware vsin/vcos
 * (they still call libm), so the "intrinsic" path is CMSIS-DSP.
 * ===================================================================== */
#ifndef DSP_TRIG_IMPL
  #if defined(ARM_MATH_CM0) || defined(ARM_MATH_CM0PLUS) || defined(ARM_MATH_CM3) \
   || defined(ARM_MATH_CM4) || defined(ARM_MATH_CM7) || defined(ARM_MATH_CM33) \
   || defined(ARM_MATH_A5)  || defined(ARM_MATH_NEON)
    #define DSP_TRIG_IMPL 1
  #else
    #define DSP_TRIG_IMPL 0
  #endif
#endif

#if DSP_TRIG_IMPL == 1
  #include <arm_math.h>
  #define dsp_sinf(x) arm_sin_f32(x)
  #define dsp_cosf(x) arm_cos_f32(x)
  /* arm_sqrt_f32 takes an output pointer, so wrap it in a float-returning fn. */
  static float dsp_sqrtf(float x) { float r; arm_sqrt_f32(x, &r); return r; }

#elif DSP_TRIG_IMPL == 2
  static const float dsp_sin_lut[129] = {
      +0.0000000f, +0.0122715f, +0.0245412f, +0.0368072f, +0.0490677f, +0.0613207f, +0.0735646f, +0.0857973f,
      +0.0980171f, +0.1102222f, +0.1224107f, +0.1345807f, +0.1467305f, +0.1588581f, +0.1709619f, +0.1830399f,
      +0.1950903f, +0.2071114f, +0.2191012f, +0.2310581f, +0.2429802f, +0.2548657f, +0.2667128f, +0.2785197f,
      +0.2902847f, +0.3020059f, +0.3136817f, +0.3253103f, +0.3368899f, +0.3484187f, +0.3598950f, +0.3713172f,
      +0.3826834f, +0.3939920f, +0.4052413f, +0.4164296f, +0.4275551f, +0.4386162f, +0.4496113f, +0.4605387f,
      +0.4713967f, +0.4821838f, +0.4928982f, +0.5035384f, +0.5141027f, +0.5245897f, +0.5349976f, +0.5453250f,
      +0.5555702f, +0.5657318f, +0.5758082f, +0.5857979f, +0.5956993f, +0.6055110f, +0.6152316f, +0.6248595f,
      +0.6343933f, +0.6438315f, +0.6531728f, +0.6624158f, +0.6715590f, +0.6806010f, +0.6895405f, +0.6983762f,
      +0.7071068f, +0.7157308f, +0.7242471f, +0.7326543f, +0.7409511f, +0.7491364f, +0.7572088f, +0.7651673f,
      +0.7730105f, +0.7807372f, +0.7883464f, +0.7958369f, +0.8032075f, +0.8104572f, +0.8175848f, +0.8245893f,
      +0.8314696f, +0.8382247f, +0.8448536f, +0.8513552f, +0.8577286f, +0.8639729f, +0.8700870f, +0.8760701f,
      +0.8819213f, +0.8876396f, +0.8932243f, +0.8986745f, +0.9039893f, +0.9091680f, +0.9142098f, +0.9191139f,
      +0.9238795f, +0.9285061f, +0.9329928f, +0.9373390f, +0.9415441f, +0.9456073f, +0.9495282f, +0.9533060f,
      +0.9569403f, +0.9604305f, +0.9637761f, +0.9669765f, +0.9700313f, +0.9729400f, +0.9757021f, +0.9783174f,
      +0.9807853f, +0.9831055f, +0.9852776f, +0.9873014f, +0.9891765f, +0.9909026f, +0.9924795f, +0.9939070f,
      +0.9951847f, +0.9963126f, +0.9972905f, +0.9981181f, +0.9987955f, +0.9993224f, +0.9996988f, +0.9999247f,
      +1.0000000f,
  };

  static float dsp_sinf(float x) {
      int neg = 0;
      float n = x * 0.15915494f;                 /* x / (2*pi)                */
      x -= (float)(long)n * 6.2831853f;          /* reduce to (-2*pi, 2*pi)   */
      if (x < 0.0f) x += 6.2831853f;             /* now [0, 2*pi)             */
      if (x > 3.14159265f) { x = 6.2831853f - x; neg = 1; }
      if (x > 1.57079633f) x = 3.14159265f - x;  /* now [0, pi/2]             */
      float idx = x * 81.487331f;                /* x / (pi/2) * 128          */
      int i = (int)idx;
      float f = idx - i;
      if (i > 127) i = 127;
      float v = dsp_sin_lut[i] + f * (dsp_sin_lut[i+1] - dsp_sin_lut[i]);
      return neg ? -v : v;
  }
  static float dsp_cosf(float x) { return dsp_sinf(x + 1.57079633f); }

  /* Fast inverse sqrt: the Quake III 0x5f3759df float->u32 bit trick plus
     one Newton iteration. No libm. Max rel. error ~0.2% - fine for the
     open-loop ripple estimate in this demo. */
  static float dsp_rsqrtf(float x) {
      union { float f; uint32_t i; } u = { x };
      u.i = 0x5f3759df - (u.i >> 1);             /* evil bit-level guess      */
      u.f = u.f * (1.5f - 0.5f * x * u.f * u.f); /* one Newton step           */
      return u.f;
  }
  static float dsp_sqrtf(float x) {
      return x <= 0.0f ? 0.0f : x * dsp_rsqrtf(x);
  }

#else
  #define dsp_sinf(x) sinf(x)
  #define dsp_cosf(x) cosf(x)
  #define dsp_sqrtf(x) sqrtf(x)
#endif
/* ===================================================================== */

/* Inplace stack (fixed capacity 5, zero heap) - sliding window for the
 * dq-frame medians. This is the only container in the 10 kHz control path. */
#define T IWin, float, (c_use_cmp), 5
#include <stc/stack.h>

/* Dynamic vec - host-side logging only (never touched by the control path). */
#define T Log, float
#include <stc/vec.h>

/* Generic algorithms (c_each, c_filter) and dynamic bitset (PWM history). */
#include <stc/algorithm.h>
#include <stc/cbits.h>

typedef struct { float d, q; } DQ;
typedef struct { float a, b, c; } ABC;
typedef struct { float kp, ki, iacc, out; } PI;

static float pi_run(PI* pi, float err) {
    pi->iacc += err;
    pi->out = pi->kp * err + pi->ki * pi->iacc;
    return pi->out;
}

/* Median of a[0..n): insertion sort on a local array - bounded WCET,
 * no heap. Averages the two middle values for even n (never happens here
 * once the 5-sample window is full). */
static float median_n(float a[], int n) {
    for (int i = 1; i < n; ++i) {
        float x = a[i];
        int j = i - 1;
        while (j >= 0 && a[j] > x) { a[j+1] = a[j]; --j; }
        a[j+1] = x;
    }
    return (n & 1) ? a[n/2] : 0.5f * (a[n/2 - 1] + a[n/2]);
}

/* Sliding-window median of the NEWEST W samples held in an inplace stack. */
#define W 5
static float dq_median(IWin* win, float sample) {
    if (win->size == W) {                /* drop the oldest, keep newest W */
        memmove(win->data, win->data + 1, (W - 1) * sizeof(float));
        --win->size;
    }
    IWin_push(win, sample);
    float a[W];
    memcpy(a, win->data, win->size * sizeof(float));
    return median_n(a, (int)win->size);
}

/* Clarke + Park: balanced 3-phase currents -> (id, iq) at rotor angle theta. */
static DQ clarke_park(ABC s, float theta) {
    float ia = s.a, ib = s.b, ic = s.c;
    float  al = 0.6666667f * (ia - 0.5f*ib - 0.5f*ic);          /* ia+ib+ic = 0 */
    float  be = 0.6666667f * (0.8660254f*ib - 0.8660254f*ic);
    float c = dsp_cosf(theta), s_ = dsp_sinf(theta);
    return (DQ){ al*c + be*s_, -al*s_ + be*c };
}

/* Inverse Park + Clarke: (id, iq) -> balanced 3-phase quantities. */
static ABC inv_dq(DQ v, float theta) {
    float c = dsp_cosf(theta), s_ = dsp_sinf(theta);
    float  al = v.d*c - v.q*s_, be = v.d*s_ + v.q*c;
    return (ABC){ al, -0.5f*al + 0.8660254f*be, -0.5f*al - 0.8660254f*be };
}

int main(void) {
    /* Machine + control parameters (10 kHz PWM, current loop at ~800 Hz) */
    const float R   = 1.0f;                 /* stator resistance [ohm]     */
    const float Ld  = 1e-3f, Lq = 1e-3f;    /* inductances [H]             */
    const float psi = 0.05f;                /* flux linkage [Wb]           */
    const float w   = 100.0f;               /* electrical speed [rad/s]    */
    const float Ts  = 1e-4f;                /* sample period [s]           */
    const float psi6 = 0.0015f;             /* 6th-harm flux ripple (real
                                             5th/7th harmonics -> 6th dq)  */
    const float iq_ref = 1.0f, id_ref = 0.0f;
    const int N = 500;                      /* simulation ticks            */

    IWin win_d = {0}, win_q = {0};          /* dq median windows (inplace) */
    Log iq_true = {0}, iq_raw = {0}, iq_filt = {0};   /* host-side logs     */
    cbits pwm = cbits_with_size(2 * N, false);        /* PWM vector history */

    PI pi_d = {5.f, 0.5f, 0.f, 0.f}, pi_q = {5.f, 0.5f, 0.f, 0.f};
    float theta = 0.f, id = 0.f, iq = 0.f;

    for (c_range(k, N)) {                   /* ---- 10 kHz control loop ---- */
        theta += w * Ts;

        /* 1) Sensor: reconstruct a balanced abc set from the true dq state
              (ia + ib + ic == 0, phases 120 degrees apart), then inject a
              single-sample ADC glitch on phase b. */
        ABC s = inv_dq((DQ){id, iq}, theta);
        if (k == 40) s.b += 4.0f;                       /* ADC glitch      */

        /* 2) Forward Clarke + Park: abc -> measured (id, iq) */
        DQ m = clarke_park(s, theta);

        /* 3) Reject the glitch with a sliding median in the dq frame,
              where the signals are DC in steady state (newest 5 samples). */
        float fd = dq_median(&win_d, m.d);
        float fq = dq_median(&win_q, m.q);

        /* 4) PI current regulators + feedforward (bemf, cross-coupling) */
        DQ v = { pi_run(&pi_d, id_ref - fd), pi_run(&pi_q, iq_ref - fq) };
        v.d -= w * Lq * iq;
        v.q += w * psi + w * Ld * id + R * iq_ref;

        /* 5) Electrical plant: L di/dt = v - R i - cross-coupling - bemf.
              A 6th-harmonic flux ripple disturbs the back-EMF. */
        float bemf = w * (psi + psi6 * dsp_sinf(6.f * theta));
        float new_id = id + (v.d - R*id + w*Lq*iq) * Ts/Ld;
        float new_iq = iq + (v.q - R*iq - w*Ld*id - bemf) * Ts/Lq;
        id = new_id;
        iq = new_iq;

        /* 6) Space-vector modulation: log the active switching vector. */
        ABC duty = inv_dq(v, theta);
        cbits_reset(&pwm, 2*k);
        cbits_reset(&pwm, 2*k + 1);
        if      (duty.a > 0) cbits_set(&pwm, 2*k);
        else if (duty.b > 0) cbits_set(&pwm, 2*k + 1);

        /* 7) Host-side logging (not part of the control path). */
        Log_push(&iq_true, iq);
        Log_push(&iq_raw,  m.q);
        Log_push(&iq_filt, fq);
    }

    /* ---- results (post-processing on the host side) ---- */

    /* Settling time: first tick after which iq stays within 2% of iq_ref. */
    isize_t last_off = -1;
    for (c_range(k, N))
        if (fabsf(iq_true.data[k] - iq_ref) >= 0.02f) last_off = k;
    printf("iq settles to %.3f A (ref %.1f A) in %.2f ms (2%% band)\n",
           iq_true.data[N-1], iq_ref, (last_off + 1) * Ts * 1000.0);

    /* Glitch rejection: what the PI saw at the glitch tick (k = 40). */
    printf("glitch@40: raw measured iq deviates by %+.2f A, median-filtered by %+.3f A\n",
           iq_raw.data[40]  - iq_true.data[40],
           iq_filt.data[40] - iq_true.data[40]);

    /* 6th-harmonic disturbance: analytic open-loop ripple vs measured
       closed-loop residual (steady-state, last 100 ticks). */
    float open_ripple = w * psi6 / dsp_sqrtf(R*R + (6.f*w*Ld)*(6.f*w*Ld));
    float lo = 1e30f, hi = -1e30f;
    for (c_range(k, N - 100, N)) {
        float x = iq_true.data[k];
        if (x < lo) lo = x;
        if (x > hi) hi = x;
    }
    float closed_ripple = 0.5f * (hi - lo);
    printf("6th-harm iq ripple: %.3f A open-loop -> %.3f A closed-loop (%.0fx rejection)\n",
           open_ripple, closed_ripple, open_ripple / closed_ripple);

    /* Number of settled samples (c_filter demo) and PWM pattern (cbits). */
    int nsettled = 0;
    c_filter(Log, iq_true, true
        && (fabsf(*value - iq_ref) < 0.02f) && (++nsettled, true)
    );
    printf("settled samples: %d/%d (c_filter)\n", nsettled, N);
    printf("PWM switching pattern (first 40 ticks): ");
    cbits_print(&pwm, stdout, 0, 80);
    puts("");

    Log_drop(&iq_true);
    Log_drop(&iq_raw);
    Log_drop(&iq_filt);
    cbits_drop(&pwm);
    return 0;
}
