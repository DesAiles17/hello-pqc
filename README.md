# hello-pqc — PQC library experiments (Rust)

Мета: перевірити, що Rust-бібліотеки для пост-квантових підписів (ML-DSA / Falcon) **збираються** та **успішно підписують/верифікують** повідомлення, і зафіксувати сумісність версій.

---

## Environment & Versions

> Замініть на фактичні значення з вашої машини.

```bash
rustc --version
cargo --version
Libraries (from Cargo.lock)
bash
Копіювати код
cargo tree | grep -E "pqcrypto|oqs"
Вписати сюди коротко:

pqcrypto-mldsa = x.y.z (ML-DSA-44/65/87)

pqcrypto-falcon = x.y.z (Falcon-512/1024)

oqs = x.y.z (bindings to liboqs)

OS / CPU (наприклад, macOS 14.x, Apple Silicon)

Project Layout
bash
Копіювати код
hello-pqc/
├─ Cargo.toml
├─ src/main.rs
└─ examples/
   ├─ pq_mldsa44.rs      # ML-DSA-44 via pqcrypto-mldsa
   ├─ pq_falcon512.rs    # Falcon-512 via pqcrypto-falcon
   └─ oqs_signs.rs       # ML-DSA-44 & Falcon-512 via oqs
Quick Start
bash
Копіювати код
# (перший раз) достав корисні інструменти
rustup component add rustfmt clippy

# запустити приклади
cargo run --example pq_mldsa44
cargo run --example pq_falcon512
cargo run --example oqs_signs
Очікуваний результат
Кожна команда завершується без помилок і друкує щось на кшталт:

Копіювати код
ML-DSA-44 OK; pk=...B sig=...B
Falcon-512 OK; pk=...B sig=...B
MlDsa44 OK
Falcon512 OK
Notes on Compatibility
Dilithium → ML-DSA: у Rust-екосистемі сучасний crate називається pqcrypto-mldsa (не pqcrypto-dilithium).

Falcon: використовуємо pqcrypto-falcon або oqs (Algorithm::Falcon512/1024).

Для oqs інколи потрібні інструменти збірки C/C++:

macOS: brew install cmake ninja openssl@3

Ubuntu/Debian: sudo apt install cmake ninja-build pkg-config libssl-dev

Windows: встановити CMake + “Desktop development with C++” (MSVC)

Outcome / Completion Checklist
 Проведено коротке дослідження доступних Rust PQC бібліотек (pqcrypto-mldsa, pqcrypto-falcon, oqs).

 Приклади збираються та виконуються: pq_mldsa44, pq_falcon512, oqs_signs.

 Підпис і верифікація проходять успішно (див. очікуваний вивід).

 Зафіксовано версії тулчейну та бібліотек у розділі Environment & Versions.