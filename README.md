# NORM-EDR

**NORM (Normal EDR)** is an experimental **kernel-mode EDR research project**
focused on **explainable detection** rather than silent blocking.

Instead of assigning scores or killing processes, NORM shows:
> **_why a binary looks suspicious_**

This project is built step-by-step in public as a learning and research journey.

---

## 🎯 What NORM Currently Detects (v0.1)

- Process creation tracking (kernel)
- Static DLL imports (PE Import Table)
- Runtime / dynamically loaded DLLs
- Correlation between:
  - Declared (static) imports
  - Undeclared (dynamic) DLL loads
- Baseline suppression for common Windows DLLs
- Clear, human-readable kernel alerts explaining the signal

## 🔧 Build & Lab Setup

NORM is a kernel-mode driver and requires a dedicated lab environment.

A complete walkthrough covering:
- VM setup
- Test signing
- Driver compilation
- Driver loading

is available here:

📺 **How to Compile & Run NORM (Kernel Lab Setup)**  
👉 YouTube: https://www.youtube.com/watch?v=8NHgK_OSKj8

Written build steps are intentionally omitted to keep documentation
in sync with the video series.

## 📜 Disclaimer

This project is:
- For **learning**
- For **research**
- For **educational labs**

**Not production-ready.**
Do not deploy on real systems.

---

## ☕ Support

If you find this project useful and want to support continued development, 
you can help by buying me a coffee.

Your support helps cover:
- Lab infrastructure and VM crashes
- Kernel debugging time
- Writing documentation and blog posts
- Creating educational YouTube content

👉 [**Support me on Buy Me a Coffee**](https://buymeacoffee.com/amberchalia)


## Learn More
Read about my challenges and technical insights on my blog: [rootfu.in](https://rootfu.in).
