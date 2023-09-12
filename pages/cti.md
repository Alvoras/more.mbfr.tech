# CTI
## Melody

!!! info

	+ Source : [https://github.com/bonjourmalware/melody](https://github.com/bonjourmalware/melody)
	+ Inspiration : [Règles Sigma](https://github.com/SigmaHQ/sigma), [viz.greynoise.io](https://viz.greynoise.io/)
	+ Langage : Golang

Melody est une sonde de couche 2 permettant d'enregistrer et de tagger l'ensemble des paquets reçus via un système de règles sur-mesure.

Cet outil est pensé pour être dispersé sur Internet afin d'en capter le "bruit de fond".

Plusieurs cas d'usages existent :

+ Posséder un "négatif" du traffic négligeable pour réduire le bruit lors d'une analyse d'activité réseau
+ Analyser les motifs récurrent pour en extraire des tendances
+ Suivre l'évolution de la menace lors de la correction d'une vulnérabilité critique 
+ Surveiller l'émergence d'une campagne d'exploitation sur une ou un ensemble de technologies données
+ Rejouer une capture réseau pour en extraire des paquets spécifiques grâce à des règles dédiées

Un serveur HTTP/S intégré offre la possibilité d'émuler une application web vulnérable en plaçant simplement les fichiers à afficher aux chemins adéquats. Cela peut s'avérer utile, par exemple, si l'on souhaite observer le comportement des scanners en fonction des applications exposées.

Pour plus de détails, une documentation est disponible sur [https://bonjourmalware.github.io/melody/](https://bonjourmalware.github.io/melody/).  

### Aperçu

<figure>
	<a href="https://github.com/bonjourmalware/melody/blob/master/readme/melody_demo.gif" target="_blank"><img src="https://raw.githubusercontent.com/bonjourmalware/melody/master/readme/melody_demo.gif" /></a>
  <figcaption>Aperçu du flux de paquets reçus par une sonde Melody</figcaption>
</figure>

<figure>
  <a href="https://raw.githubusercontent.com/bonjourmalware/melody/master/readme/melody_demo_dash.png" target="_blank"><img src="https://raw.githubusercontent.com/bonjourmalware/melody/master/readme/melody_demo_dash.png" /></a>
  <figcaption>Exemple de dashboard qu'il est possible de réaliser à partir des données récoltées</figcaption>
</figure>

## Meloctl

!!! info

	+ Source : [https://github.com/bonjourmalware/melody](https://github.com/bonjourmalware/melody) (en cours de finalisation avant sa première release)
	+ Langage : Golang

Meloctl est un programme destiné à faciliter l'utilisation de Melody en prenant en charge les opérations suivantes :

+ Installation et mise à jour de la sonde
+ Intégration à systemd
+ Intégration à supervisor 
+ Validation du fichier de configuration
+ Création de règles depuis la CLI ou de manière interactive
+ Validation des règles fichier par fichier ou par dossier complet 
+ Mise à jour du ruleset

### Aperçu

<figure>
  <img src="/assets/cti/meloctl/media/check_demo.png" />
  <figcaption>Aperçu de la validation des règles</figcaption>
</figure>


<figure>
	<video alt="Meloctl Create Rule Demo" width="100%" controls>
	  <source src="/assets/cti/meloctl/media/create_rule_demo.webm" type="video/webm">
	Your browser does not support the video tag.
	</video>
  <figcaption>Création d'un template de règle</figcaption>
</figure>


## lab.bonjourmalwa.re

!!! info

	+ Inspiration : [viz.greynoise.io](https://viz.greynoise.io/)
	+ Langage : Golang, VueJS

Cette interface est disponible publiquement et propose un jeu de données issu des 30 derniers jours de récolte d'une sonde Melody. Elle a été créée afin d'offrir une interface d'analyse complémentaire à Kibana, complètement rigide mais plus rapide et qui permet de pivoter sur l'ensemble des paramètres récoltés.

De plus, elle me permet d'être en mesure de monter des pages synthétisant des informations regroupées d'une manière qu'il est difficile de reproduire via un moteur de visualisation comme Kibana.


### Aperçu

<center>
<video alt="lab.bonjourmalwa.re Demo" width="100%" controls>
  <source src="/assets/cti/lab.bonjourmalwa.re/media/demo.webm" type="video/webm">
Your browser does not support the video tag.
</video>
</center>

