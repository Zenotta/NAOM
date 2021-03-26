# Notarised Append Only Memory (NAOM)

Le repo NAOM contient tout le code nécessaire pour configurer et interagir avec une instance locale de la blockchain Zenotta. 
D'autres options de langue peuvent être trouvées ici:

- [English](https://gitlab.com/zenotta/naom/-/blob/main/README.md)
- [中文](https://gitlab.com/zenotta/naom/-/blob/main/README.zhs.md)
- [Deutsch](https://gitlab.com/zenotta/naom/-/blob/main/README.de.md)
- [Afrikaans](https://gitlab.com/zenotta/naom/-/blob/main/README.af.md)

Si vous souhaitez aider à la traduction, ou repérer une erreur, n'hésitez pas à ouvrir une nouvelle merge request.

..

## Pour Commencer

Pour le développement, NAOM nécessite les installations suivantes:

- [Rust](https://www.rust-lang.org/tools/install)

Vous pouvez cloner ce dépôt et exécuter les tests comme suit:

```
cargo build
cargo test
```

Avant de mettre du code dans ce dépôt, il est conseillé d'exécuter `make` depuis le compte root pour formater et lint le code pour le CI.

..

## Utilisez

L'exécution de `cargo run --bin main` listera actuellement tous les actifs sur l'instance locale. NAOM n'est généralement pas destiné à être utilisé directement, et est plutôt destiné à être utilisé à partir d'autres programmes qui nécessitent un accès à la structure de données de la blockchain.