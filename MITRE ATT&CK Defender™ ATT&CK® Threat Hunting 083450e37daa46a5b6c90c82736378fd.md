# MITRE ATT&CK Defender™ ATT&CK® Threat Hunting

## 1.2. Approches de detection traditionelles

- **Precision : Ratio of true positives to total results**
    
    **→ Good precision : very few false positives**
    
- **Recall : Ratio of true positives to total relevant (malicious) events**
    
    **→ Good recall : very few false negatives**
    

- Basées sur la signature → nominatif : Définit le mal/mauvais comme un moyen mesurable.
    
    → Dessine un nouveau cercle rouge autour de chaque triangle détecté comme étant un triangle.
    
- Allow-List : Ce qui est dedans est autorisé, le reste est définit comme mauvais.
    
    → Liste les smilyes verts et bloque le reste.
    
- Anomaly-based : Similaire à la detection par allow-list, se base sur des statistiques, considère que les activités normales sont benignes et que autre chose est mauvais.
    
    → Alerte sur les triangles et les smileys qui ne sont pas proches d’un cluster.
    
    ![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled.png)
    
    (Recall et precision en conflit)
    

**Detection basée sur la signature:** Définie explicitement une menace comme ayant certaines caractéristiques, basées sur des menaces antérieures. → Ex: expressions régulières dans le hexdump d’un fichier binaire ou capture de paquets. Beaucoup utilisent cette approche. Cette méthode n’aide  pas trop la première victime de l’attaque pour des raisons évidentes.

→ Offre tout de même une bonne précision

→ l’entité receveuse de la signature doit avoir un gestionnaire de signature qui met à jour les signatures et supprime celles qui ne sont plus utilisées.

→ historiquement inefficaces et les attaques modernes sont tellement dynamiques que les signatures statiques ne servent plus à grand chose.

**Violation de l’Allow-List :** 

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%201.png)

**Anomaly-based :**

→ développe une base statistique autour de la “normalité”.

→ défini le normal comme bon et l’anormal comme mauvais

Exp: Nouvelles @IPs, domaines, DGA, session FTP longuement anormale, nouveaux comportements d’utilisateurs. L’upload size (si activité dépasse l’upload s”ize on déclenche une alerte)

→ Permet de détecter de nouvelles attaques d’adversaires, bien utile dans les environnements où les comportements normaux sont bien définis, mais a besoin de s’adapter aux changements, demande + d’investigations, les adversaires peuvent calquer leur comportement comme étant normal, risque que les comportement normaux soient flagué comme étant anormaux (applications, réseau..). 

→ Les bons (vrais) adversaires, savent très bien quelle approche défensive utilisent les org.

# **Dimensions de détection:**

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%202.png)

High precision → peu de fausses alarmes

High recall → peu de détections râtées

La precision et le recall sont en tension entre eux.

## 1.3. Approche: TTP-Based Detection

Cette approche est un complément aux 3 méthodes précédentes.

**IOCs: Indicators of compromission**

→ Typically, known to be malicious because they have already been used in an intrusion.

→ Therefore, they do not help initial victims targeted before the IOCs are discovered, shared and implemented by others.

→ Adversary can easily change them between and within operations.

**All this things gives advantage to the adversary.**

**TTPs: Technics, tactics and procedures**

→ Limited by functionality of the underlying technology they target, expensive to develop and maintain an interface, limited interface providers. 

**But gives advantage to the defender !**

Diving deeper in this difference with the pyramin of pain (David Bianco’s Pyramid of  Pain)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%203.png)

Figure représentatrice du niveau de difficulté que rencontrent les adversaires (plus facile de changer le hash d’un malware plutot que de créer des TTP !).

***Certaines de ces actions peuvent êtres scriptées !***

**Hashs :** Un adversaire peut changer un hash (ex: sha256) en cheangeant un seul bit dans son programme. Ca peut également être le hash d’autre chose (ex: échange crypté). Facile à faire et n’affecte en rien le fonctionnement d’un programme et de ses fonctions. → Secondes

**Adresses IP :** Peut être distribué dynamiquement et changé regulièrement. Peut n’indiquer qu’un NAT, un proxy ou un mandataire, soit pas la vraie source. → Minutes

**Noms de domaine :** Enregistrés dans un registrar, renvoie à une adresse IP, besoin d’enregistrer un nouveau nom de domaine et le synchroniser avec le malware. → Minutes

**Artefacts Réseau/Machine :** Ex: Fichiers suspects, noms de clés de registres, Typos… Pour ce faire, l’attaquant a besoin de comprendre l’artefact qu’il laisse derrière lui et avoir les compétences pour le modifier sans modifier le coeur fonctionnel du malware. → Hours to days

Imaginons que le détecter a dans sa liste noire les process comprenant le string “Mimikatz”, l’attaquant aura besoin de recompiler son truc sans ce terme.

**Tools:** Si l’outil se fait reconnaitre (flag), il est compliqué pour l’attaquant de continuer à l’utiliser. L’adversaire a besoin de bien comprendre son outil d’attaque, il a besoin d’entrainement pour switcher d’outil et certains outils sont compliqués à changer ou demandent énormément de temps.

**TTPs (Tactics, technics and procedures):** Le plus compliqué pour un attaquant à changer ou à implémenter. Limité par les fonctions organiques de la technologie cible (ex: Windows). Les tactics changent rarement. Des recherches profondes sont nécessaires pour découvrir de nouvelles techniques.

Challenging to re implement existing techniques to create a new tool, creating new techniques is require even deeper expertise in the target systems or protocols and often extensive and expensive research. The new technics must interact with the existing functionalities of the target system whether that **APIs, operating system APIs, protocol specs or even CPU instructions or physical limitations of hardware. C’est sur cela que l’on va se concentrer** 

→ Limités par les fonctionnalités organiques de la technologie cible (e.g., Windows).

→ Les tactics changenet rarement

→ Recherches approfondies pour trouver de nouvelles techniques.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%204.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%205.png)

To summarize :

→ TTPs are very diffcult for adversaries to create and modify.

→ **Defenses focused on TTPs** are likely to have large and lasting benefits.

→ All these approaches are valuable and complementary.

→ This course focuses on how to apply ATT&CK to hunting, and therefore utilizes a TTP-based approach. 

- [https://docs.microsoft.com/en-us/windows/win32/secgloss/s-gly](https://docs.microsoft.com/en-us/windows/win32/secgloss/s-gly)
- [https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)

## 1.4. Prioritization

Comment prioritiser lors du développement de hunting afin de tirer un maximum des ressources qui sont parfois limitées.

**Purpose Driven**

→ Aligner l’équipe et les parties prenantes avec la stratégie de sécurité de l’organisation.

→ Optimiser les ressources limitées

→ Identifier les composants pertinents de l’environnement et ls techniques malicieuses

→ Activer la mesure du progrès et des succès

→ Not all techniques are equally suitable for analytic development.

→ Things change → keep prioritization updated.

- Adversaries develop new techniques
- OS and softs add new functionality
- New technos and soft are added to environment
- Ressources like ATT&CK improve and grow

**********Prioritizing based on technology**********

→ Quelles sont les technologies existantes ?

→ La liste peut ne pas être complète → d’autres technologies peuvent exister comme :

- Labs et réseaux de développement
- web facing systems / firewalls / proxies ..
- ICS/SCADA networks (système de contrôle et d’aquisition de données), IOT, BYOD ..

→ La liste peut ne pas être assez détaillé → OS version numbers, configurations …

→ Quels analytics et TTPs s’appliquent à cet environnment ?? Does the plan for their implementation need to be adapted ??

******************Prioritizing based on business impact******************

Start with failure scenario and trace back through the system architecture to identify key systems and techniques.

In my environment : 

- Which systems / accounts have access to sensitive information ?
- Which systems are single points of failure for my key operations ? What are the path from somewhere like the internet, that an adv would take to achieve his goal ?
- Which techniques is an adversary likely to use to target my business ?
- Does CTI indicate specific Groups likely to target my type of business or sector? Which techniques do they commonly use ?

→ Peut être sujet à cyber environnements qui appellent à plusieurs analyses, résultant dans différentes priorités.

**Prioritazing based on behavior**

→ Comment les défenses sont positionnées par rapport aux techniques qui concernent mes technologies et mon business ?

→ Quelles sont les lacunes qui existent dans mes défenses et moyens de mitigation ?

→ Quelles techniques sont bien détectées dans mon environnement ? 

→ Quelles nouvelles détections complémenteraient le mieux mes défenses existantes ?

→ Quels comportements sont courrament vus en CTI ?

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%206.png)

[https://www.cloudflare.com/fr-fr/learning/security/glossary/what-is-lateral-movement/](https://www.cloudflare.com/fr-fr/learning/security/glossary/what-is-lateral-movement/)

→ a SOC assessment can help understand the current defensive posture : [https://www.crowdstrike.fr/services/suis-je-mature/soc-evaluation/](https://www.crowdstrike.fr/services/suis-je-mature/soc-evaluation/)

→ Adversary emulation and purple teaming can test the current defenses and might help eliminate current gaps.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%207.png)

## 1.5. TTP Hunting Methodology Overview

La grosse hypothèse qui drive le hunting peu importe notre approche : 

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%208.png)

To detect malicous activity in cyber, we must discover, characterize, and understand that malicious activity.

How we apply the adversary behaviour represented in ATT&CK to develop and effectively deploy analytics that deploy that behaviour ?

**V-Shaped model used :**

Analytics → To notify an analyst or to respond to the malicous activity, we must develop and validate analytics that reflect that activity.

Data → Analytics require input data that will provide visibility of the malicious behavior.

Left side of the V-model:

Discovering, characterizing, researching and planning using :

- Behavior descriptions
- Analytic hypotheses
- Data requirements

Right side :

- Implementing, testing, refining, validating and executing by collecting data.
- Validating analytics
- Hunting !

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%209.png)

Steps doesn’t have to be followed in order.

Community work help on those steps.

# Module 2 - Développer des hypothèses et des analyses abstraites.

**Concretly, what is an hypothesis ?**

- An hypothesis is defined as a “supposition or proposed explanation made on the basis of limited evidence as a starting point for further investigation“
- Describe a suspect reason why something is happening.

******************************Hypothesis creation :******************************

- is truly an iterative process
    - Evaluating falsifiability exposes potential false alarms scenarios.
    - Those scenarios help refine hypothesis to focus on malicious use.
- Written in a simple language.

**Biais in CTI :**

Threat intelligence model biais (e.g. MITRE ATT&CK) :

- Visibility biais
- Victim biais
- Novelty biais

Defenders introduce biais when using CTI as : 

- Availability bias / Biais de disponibilité :
    - Se baser uniquement sur des données existentes lors de la priorisation des techniques
    - Cueillir les techniques et comportements familiés pour + d’investigations
- Anchoring bias / Biais d’ancrage :
    
     → Lose of other useful informations provided by other data sources. 
    
    - Se baser uniquement sur le traffic réseau comme source de données parceque c’est ce que le rapport CTI mentionne.

Dealing with Biases :

→ Document rationale on how decisions were reached

→ Collaborate with teammates to gain different perspectives and debate decisions and assumptions

→ Revisit assumptions throughout the threat hunting process to ensure they still apply in light of new information.

 - Why choosing a particular hypothesis ? What other hypothesis you discarded or deprioritize ? and what you believe about the environment you are defending ?

**Choosing a technique :**

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2010.png)

→ Find a good balance on those caracteristics to determine how to best focus the efforts.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2011.png)

→ Reading what others done to not end up doing redundant work !

The other ressources : Att&ck, sigma, the hunters playbook and others to extract infos for malicious behaviour.

→ Engage with the community on my ideas !

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2012.png)

 

### Finding Low-Variance behaviors - Developing hypotheses & abstract analytics

****Variance scale for Attack Indicators :**** 

- It is possible for an adversary to carry out an attack tactic or technique using varying implementation methods.
- Looking into these methods, we can “plot” these attack indicators on a variance scale to get a sense of their robustness.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2013.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2014.png)

**Invariant behaviors :**

**Activités fondamentales propres à une technique** qui ne peuvent pas être changées en alterant la procédure d’implémentation de cette technique (e.g. what tool execute it ?).

Si l’adversaire arrive à contourner les hypothèses pendant son execution de la technique → l’hypothèse ne se focus pas sur les comportements invariants.

******************************************Developing behavior-based hypothesis :******************************************

1. **Choose a technique**
    
    ********************Driven by hypothesis********************
    
2. **Define scope for behavior**
    
    *****************************************Intended platforms, implementations, and functionality***************************************** 
    
3. **Open source research**
    
    *************Data sources, implementation methods, general attack flow, etc.*************
    
    ************Reading docs of OS/Softwares/APIs************
    
4. **Hands-On Investigation**
    
    ****************************Emulate / Purple Team Behavior****************************
    
    ********************Create Causal graphs********************
    
    *******************************Reverse engineering, debugging, executing the behavior ourselves, examining relevant logs, emulation*******************************
    

Ces étapes sont des process pour trouver des comportements à faible variance → Le focus est sur le **Recall**.

1. **********************************************Define Additional Conditions********************************************** 
    
    *************************************************Identify (probable) benign vs malicious use cases*************************************************
    
    ****Leads to Hypothesis Refinement and Abstract Analytic****
    

Cette étape améliore la précision

Cette procédure est itérative, elle peut être adaptée à différentes situations, les invariants ne sont pas nécessairement malicieux.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2015.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2016.png)

### Chercher les comportements à faible variance - Développement d’hypothèses et analyses abstraites

*Comment conduire des recherches afin de trouver des comportements à faible variance ?*

→ Recherches open-sources pour trouver les caractéristiques

[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)

Ressources open-source :

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2017.png)

- Open source research plays a key role in identifying low-variance behaviors.
- Gaining a deeper understanding of usage and implemention differences of an attack can help in identifying its low variance behaviors.

### Investigating low-variance behaviors

Hands-on investigations to find low-variance behaviors.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2018.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2019.png)

 

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2020.png)

### Refining hypothesis

- Which events / artifacts are common across technique implementations ?
    
    **→ How can it be invoked by an adversary ?** 
    
    Pour l’exemple de Scheduled task, on a vu que l’attaquant pouvait faire ca via : at.exe / schtasks.exe / taskschd API / task scheduler API.
    
    **→ What will the system do ?**
    
    Task scheduled → Registry change / DLL Loads / File writes / Network connections 
    
    **→ Which activities are avoidable / optional ?**
    
    Is it fundamental to executing the technique ? → Invariant behaviors !
    
- How would the Adversary’s Activity look different from benign usage ?
    
    → Considering how typical user might exhibit this behavior
    

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2021.png)

**Behavior desc :** Un adversaire peut utiliser la plnaification de tâches afin d’éxécuter des programmes au lancement du système a des possibles fins de persistence. Ces mécanismes peuvent aussi être abusés afin d’éxécuter un process dans le contexte d’un compte spécifique (comme un compte avec des privilèges/permissions élevés)… Une tâche peut également être planifiée sur un système distant.

**Hypotèse initiale :** Si une tâche est planifiée, un adversaire peut essayer d’obtenir la persistence, conduire des executions à distance, ou augmenter ses privilèges.

Problèmes : Pas trop de détails / vague. → **High Level hypothesis à rafiner**

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2022.png)

******************Refined hypothesis : Local schedulin g****************** 

**Itération 1 :** 

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2023.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2024.png)

************************Itération 2 :************************

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2025.png)

************************Itération 3 :************************

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2026.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2027.png)

### Develop Abstract Analytics

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2028.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2029.png)

### Tirer parti des ressources externes - ****************************Leveraging external ressources****************************

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2030.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2031.png)

[Analytic Coverage Comparison](https://car.mitre.org/coverage/)

[https://github.com/SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)

[detection-rules/rules at main · elastic/detection-rules](https://github.com/elastic/detection-rules/tree/main/rules)

[CAR-2013-08-001: Execution with schtasks](https://car.mitre.org/analytics/CAR-2013-08-001/)

# Module 3 - Determining Data requirements

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2032.png)

## 3.1. Balancing Data requirements

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2033.png)

****************************************************Key is to understand your data and implications for precision and recall, purpose is to balance recall and precision.****************************************************

- Start with hypothesis and use relevant host and network knowledge (platforms, protocols, etc.) to identify sources of data useful for detecting adversary activities.
- Data collections should include 3 dimensions :
    - **Time :** Data spanning the entire duration of the activity. → Time metric around “When”.
    - **Terrain :** Data about the networks, hosts, systems, or applications in question.
        
        → Consider where in the network/system activity will be visible. **Ex : exfiltration is visible at network perimeter, but Lateral Movement requires visibility of network connections between hosts.**
        
        → Be deliberate : Is the TTP specitif to certains OSes or devices types ? **Ex : techniques centered on virtual/sandbox environments are less relevant on thick clients.**
        
    - **Behavior :** Data of the right type, specificity, and granularity to understand the behavior and its context.
        
        → Focusing on low-variance behavior.
        

## 3.2. Diving into Data Sources

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2034.png)

W.EID 4697 → Un service a été installé dans le système.

W.EID 7040 → The start type of the IPSEC Services service was changed from disabled to auto start.

W.EID 4656 → A handle to an object was requested

W.EID 5156 → La plateforme de filtrage Windows a autorisé une connexion

Sysmon EID 3 → Network connection

Sysmon EID 12 → RegistryEvent (Object create and delete)

Sysmon EID 13 → RegistryEvent (Value Set)

[List of Sysmon Event IDs for Threat Hunting](https://systemweakness.com/list-of-sysmon-event-ids-for-threat-hunting-4250b47cd567)

- AuditD sous Linux
- Npcap and libpcap to produce events

Exemple pour Sysmon code 1 → process creation :

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2035.png)

- Starting with Win7/2008, Microsoft incorporated better host-level monitoring directly into the OS.
- Not turned by default, need to enable via Group Policy
- Command line monitoring on Win10.

Some intersting Events :

- 4624 → Login (Success)
- 4657 → Registry
- 4663 → Object Access Attempt
- 4688 → Process Creation
- 4698 → Scheduled Task Creation
- 5140 → Network Schare Access
- 5156 → WFP (Network Connection)
- 7040 → Service Manager Event
- 4695/7045 → Service creation

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2036.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2037.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2038.png)

We detect massive Low variance behaviors associated with task scheduling on Windows, such as job file creation, task registry key creation, network traffic to the task scheduler service for remote scheduling and certain DLL loads :

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2039.png)

Each of those events are associated with one or more log events or network activities sequences.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2040.png)

> 
> 
> 
> # *Protocole EPMAP*
> 
> *Ce protocole permet l’amorçage des procédures hébergées à distance (bootstrap) par la distribution de l’adresse IP et du protocole d’un service MS-RPC. Les options de ce module peuvent restreindre ces relais. Les ouvertures de connexions dynamiques sur EPMAP (portmapper) sont supportées.*
> 

Common Data Schema Examples : 

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2041.png)

## 3.3. Leveraging external ressources

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2042.png)

From ELASTIC :

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2043.png)

> ***CSCRIPT & WSCRIPT & POWERSHELL***
> 

# Module 4 - Identify and Mitigate data Collection Gaps

- Identification et validation de collection de données.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2044.png)

### 4.1. Identifying Gaps

**Identify current data sources and sensor configurations → what kind of data ?**

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2045.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2046.png)

**Evaluate network maps and system specs to identify bandwidth, processing or storage limitations for data collection**

**Review any existing coverage assessments**

**Use a threat emulation tool (Cobalt, Metasploit, etc.) to execute procedural implementation(s) for the behavior and sensor confs to ensure the required logs are generated** 

→ The intent here is not to conduct a vulnerability assessment of the network (although that might be a side-benefit). The internet is to evaluate th defender’s ability to see an adversary’s actions.

**Identify areas where coverage is lacking**

### Time, Terrain and Behavior in Data Collection Strategy

- Is the current data collection :
    - Continuous ?
    
    → If data transfered to SIEM each 24 hours → Continous : YES / Availability for analysis : data available only the next day.
    
    - Based on periodic snapchots ? How frequently ?
    - Only on-demand ?
- How far in the past was data collected and retained ?
- What is the retention policy for each data type ?
- How much time lag is between each event’s occurence and when it is available in the SIEM ?
- Are timestamps synchronized accross data data sources and with the SIEM ?

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2047.png)

- Behavior includes not only TTPs but also possible defense evasion and data loss.

### 4.3. Developing a Sensor Strategy - Gaps Mitigation

- In case of redundancy. For process creation for example, both sysmon and Event ID 4688 events provide similar datas.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2048.png)

- SIEM in a protected subnet.
- Analyst need access to only one system → The SIEM, its allows them to go to only one system to do their job rather than many.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2049.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2050.png)

********************************************New sensors : Reconfigure vs. Deploy********************************************

- It is often easier to configure an existing sensor than to to deploy a new one.
- Typically, fewer approvals are required.
- if SIEM/Log aggregator is already in place, new data flows are not needed.
- Existing sensors might not be capable of sufficient collection across time, terrain and behavior dimensions.

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2051.png)

### 4.4. Using Alternative Data Sources And Analytics

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2052.png)

- Analytic Logic

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2053.png)

### 4.5. Communicating with Network Managers

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2054.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2055.png)

### 4.6. Validating Configuration

L’objectif est de s’assure que les configurations de capteurs fonctionnent comme prévu.

→ Ensure all excepted data arrives from sensor(s)

→ Ensure data is being parsed correctly

→ Ensure data is being generated for each malicious behavior

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2056.png)

# Module 5 - Implement and Test Analytics

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2057.png)

### 5.1. Implementing Analytics

**Transforming Pseudocode to Analytics :**

- Convert pseudocode logic and field names to conform with the analytic platform
- Account for unique aspects of the analytic platform
- Analytic development may need multiple iterations
- ******************************Analytic Platforms****************************** such as Splunk or Elastic Stack

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2058.png)

→ \\\\ Means escaping 2 backslashes on Kibana.

### 5.2. Validating analytics

**→ Are analytic working as expected ?**

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2059.png)

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2060.png)

 → Iterative steps

![Untitled](MITRE%20ATT&CK%20Defender%E2%84%A2%20ATT&CK%C2%AE%20Threat%20Hunting%20083450e37daa46a5b6c90c82736378fd/Untitled%2061.png)