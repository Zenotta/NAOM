# Notarised Append Only Memory (NAOM)

Das Naom-Repo enthält den gesamten Code, der zum Einrichten und Interagieren mit einer lokalen Instanz der Zenotta-Blockchain benötigt wird.

Weitere Sprachoptionen können Sie hier finden:

- [English](https://gitlab.com/zenotta/naom/-/blob/main/README.md)
- [中文](https://gitlab.com/zenotta/naom/-/blob/main/README.zhs.md)
- [Française](https://gitlab.com/zenotta/naom/-/blob/main/README.fr.md)
- [Afrikaans](https://gitlab.com/zenotta/naom/-/blob/main/README.af.md)

Wenn Sie bei der Übersetzung helfen möchten oder einen Fehler entdecken, können Sie eine neue Merge-Request öffnen.

## Entwicklung

Für die Entwicklung benötigt NAOM die folgenden Installationen:

- [Rust](https://www.rust-lang.org/tools/install)

Sie können dieses Repo klonen und die Tests wie folgt ausführen:

```
cargo build
cargo test
```

Bevor Sie den Code ins Repo hochladen, sollten Sie `make` ausführen, um den Code für das CI zu formatieren und linsen.

..

## Benutzen

Das Ausführen von `cargo run --bin main` listet derzeit alle Assets auf der lokalen Instanz auf. NAOM ist im Allgemeinen nicht für die direkte Verwendung vorgesehen, sondern für die Verwendung aus anderen Programmen, die Zugriff auf die Blockchain-Datenstruktur benötigen.