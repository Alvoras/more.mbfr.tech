# Sécurité défensive

## NoMoreDuck

!!! info

	+ Source : [https://gitlab.com/Alvoras/nomoreduck](https://gitlab.com/Alvoras/nomoreduck)
	+ Inspiration : [https://github.com/pmsosa/duckhunt](https://github.com/pmsosa/duckhunt)
	+ Langage : Golang

### Description

NoMoreDuck (dont le nom est inspiré de l'admirable projet [NoMoreRansom](https://www.nomoreransom.org/)) propose une contre-mesure aux injections de commande par l'intermédiaire d'un émulateur HID comme le RubberDucky.

### Fonctionnement

L'outil va calculer le délai moyen entre chaque frappe et déclencher l'une des actions suivantes lorsque le seuil configuré est dépassé :

+ Paranoid
	+ La session est verouillée
+ Normal
	+ L'envoi de nouvelles frappes est bloqué pendant X secondes
+ Sneaky
	+ Une touche sur X est bloquée
+ Log
	+ Invisible pour l'attaquant
	+ Un fichier est créé contenant toutes les frappes de clavier jusqu'à la levée de l'alerte

La fréquence et la durée de ces contre-mesures sont paramétrables via le fichier de configuration.

### Aperçu

<center>
<video alt="NoMoreDuck Demo" width="100%" controls>
  <source src="/assets/defsec/nomoreduck/media/demo.webm" type="video/webm">
Your browser does not support the video tag.
</video>
</center>

