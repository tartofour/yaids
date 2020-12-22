<h1 align="center">
  <a href="https://standardjs.com"><img src="https://cdn.freebiesupply.com/logos/large/2x/c-2975-logo-png-transparent.png" alt="Yaids" width="200"></a>
  <br>
  Yaids (Yet Another IDS)
  <br>
  <br>
</h1>


## Table des Matières

- Introduction
    - Fonctionnalités
    - Protocole pris en charge
- Démarrage rapide
    - [Dépendances](#d%C3%A9pendances)
    - [Installation](#installation)
    - [Utilisation](#utilisation)
    - [Fichier de règles](#Fichier-de-r%C3%A9gles)
    - [Désinstallation](#d%C3%A9sinstallation)
- Documentation du code source
    - [populate.c](#populate.c)
    - [populate.h](#populate.h)
    - [main.c](#main.c)

## Dépendances

Afin d'être en mesure de compiler le code source, le packet `libcap-dev` doit être installé sur la machine hôte.  
Pour install lib-cap:

```bash
# apt update && apt install -y libcap-dev
```

## Installation

La façon la plus facile d'installer yaids est de cloner ce dépôt et de compiler le code source à l'aide du fichier Makefile.  
Pour ce faire, exécutez les commandes suivantes depuis le terminal:

```
$ git clone https://github.com/tartofour/yaids.git
$ cd yaids
$ make
```

### Intégration au système GNU/Linux

Pour ajouter automatiquement `yaids` dans le dossier `/usr/local/bin/` et pour l'intégrer à systemd, executez le script d'installation en temps qu'administrateur:

```
# ./install.sh
```

## Désinstallation

Pour désinstaller yaids, executez le script de désinstallation en temps qu'administrateur:

```
# ./uninstall.sh
```

## Utilisation

Afin d'executer `yaids`, il est indispensable de lui fournir un fichier de règles.  
Il est également recommandé de spécifier une interface d'écoute :

```
# yaids <rules_file> [interface]
```

## Fichier de règles

Chaque ligne du fichier `rules.ids` correspond à une règle. Chaque règle définit les caractéristique permettant de la comparer avec une paquet transitant par la carte réseau. 
La régle définit également le comportement à adopter par `yaids` lorsqu'un paquet match.


### Action

Permet de définir quel type d'action sera prise par l'IDS lorsqu'une trame ethernet matche avec la règle. Actuellement, `yaids` prend uniquement en charge l'action `alert`.

### Protocole

Permet de définir le protocole sur lequel s'applique la règle. `yaids` prend en charge les protocoles suivants:

|  Protocole   |  Méthode de détection du type de payload  |
| --- | --- |
| tcp |  En fonction du protocole indiqué dans le champ `protocole` de l'entête IP.   |
| udp |  Idem  |
| icmp | Idem   |
| ftp | En fonction d'une signature dans le payload TCP  |
| http | Idem  |
| ssh |  Idem  |

### Filtrage par IP et ports
Pour ... un filtrage en fonction de l'ip ou du port. yaids prend en charge le mot-clé any.

### Options de règle
Yaids prend en charge deux type d'options :
- `content` qui permet de rechercher une chaine de caractère dans le payload d'un paquet.
- `msg` qui permet de définir la chaine de caractère à écrire dans le journal du système lors d'un match. 

## Documentation du code source

## Licence

[MIT](/usr/share/joplin/resources/app.asar/LICENSE "LICENSE"). Copyright (c) Jonathan Rasque & Benjamin Verjus
