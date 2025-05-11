# Aplicación de técnicas de Machine Learning y fuentes de inteligencia abierta para la detección proactiva de amenazas en entornos SOC

Fecha límite de entrega: 31 julio.

## PLAN DE DESARROLLO DEL PROYECTO

### 0. Idea, organización del proyecto y búsqueda de información y datos.


Familiarizarse con conceptos y plataformas de inteligencia.

Búsqueda de datasets útiles para el propósito del proyecto.
- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) / [CICIDS2018](https://www.unb.ca/cic/datasets/ids-2018.html) (Canadian Institute for Cybersecurity)
- [UNSW-NB15](https://unsw-my.sharepoint.com/personal/z5025758_ad_unsw_edu_au/_layouts/15/onedrive.aspx?id=%2Fpersonal%2Fz5025758%5Fad%5Funsw%5Fedu%5Fau%2FDocuments%2FUNSW%2DNB15%20dataset%2FCSV%20Files&ga=1)
- [CSE-CIC-IDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)
- [Bot-IoT Dataset](https://research.unsw.edu.au/projects/bot-iot-dataset) (UNSW)
- [CTU-13 Botnet Dataset](https://research.unsw.edu.au/projects/bot-iot-dataset)
- [Kitsune Network Attack Dataset](https://www.kaggle.com/datasets/ymirsky/network-attack-dataset-kitsune)

Finalmente el dataset escogido ha sido [CICIDS2018](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv), los motivos principales son:
1. Es más grande y detallado que el de 2017 (CICIDS2017) y más actualizado.
2. Al ser más extenso, es interesante desde el punto de vista del análisis de datos y da más juego a investigación y obtener información interesante. Esto también implica más diversidad y realizar más trabajo en el preprocesamiento de datos.
3. El etiquetado es multiclase, no solamente maligno o benigno.
4. Tras leer la documentación, ofrece escenarios realistas de intrusión, por lo que se acerca bastanet a un dataset que nos podamos encontrar en un entorno SOC.
5. Incluye los timestamps, por lo que se pueden relacionar eventos mediante flujos cronológicos.
6. Permite combinación con OSINT: Aunque los datos estás anonimizados, se pueden generar casos de uso en un SOC asignando IPs falsas que realmente sí hayan estado involucradas en ciberataques conocidos, y testear las consultas OSINT.


### 1. Análisis exploratorio y preprocesamiento de datos



Limpieza del dataset (detección de nulos, duplicados, datos inconsistentes).

Análisis univariante y multivariante de las variables.

Selección y/o creación de variables significativas para modelos ML.

Tratamiento del desbalanceo de clases (si aplica).

Técnicas de normalización o escalado.



### 2. Desarrollo y evaluación de modelos de Machine Learning



Comparación de distintos algoritmos (Random Forest, XGBoost, SVM, etc.).

Ajuste de hiperparámetros.

Validación cruzada y métricas de rendimiento (F1-score, ROC AUC, etc.).

Selección del mejor modelo.

Análisis de interpretabilidad (feature importance, SHAP, etc.).



#### 2.5. Simulación e inyección controlada de APTs



Justificación de la inyección de eventos (solo en caso de poca representatividad de amenazas reales en el dataset).

Diseño de registros simulados basados en campañas reales (usando MITRE ATT&CK, MISP, etc.).

Inserción de IOCs relacionados con APTs: IPs, hashes, dominios, TTPs.

Marcas diferenciadas para trazabilidad (importante para evaluación y documentación!!).



### 3. Enriquecimiento de eventos sospechosos mediante fuentes OSINT



Selección de eventos con alta probabilidad de ataque (ej. >70%).

Extracción de IOCs (IPs, hashes, dominios).

Integración con plataformas OSINT mediante API:

- VirusTotal (hash reputation, domain reports)

- AbuseIPDB (IP maliciosas)

- Shodan (exposición de servicios)

- MISP o OpenCTI (tácticas, campañas, relación con grupos APT)

- Blueliv (En revisión)

Normalización de respuestas y almacenamiento de contexto enriquecido.



### 4. Generación de informes automáticos para analistas de CTI



Creación de plantillas dinámicas de informes.

Inclusión de:

Detalles del evento técnico.

Información contextual (grupo APT, campaña, TTPs).

Reputación de IOCs.

Recomendaciones de mitigación.

Automatización del proceso (Jupyter Notebooks + librerías como ReportLab o Markdown a PDF).



### 5. Casos de uso y simulación en entorno SOC



Diseño de entorno virtual de laboratorio (ej. SOC simulado en máquina virtual).

Implementación de reglas basadas en los modelos y el enriquecimiento.

Simulación de alertas y análisis de respuestas.

Discusión sobre integración potencial con SIEM reales o plataformas SOAR.

Evaluación práctica del sistema (eficacia, falsos positivos, utilidad operativa).

## Asignaturas relacionadas

Este proyecto está directamente relacionado con varias asignaturas del máster, entre ellas:

- Ciberseguridad y tecnologías disruptivas, por su enfoque en IA y big data aplicados a la ciberseguridad.
- Gestión y equipos de respuesta ante ciberincidentes (Blue Team), dado que el modelo se plantea como parte del proceso de detección y respuesta.
- Ciberinteligencia y ciberamenazas, clave por el uso de inteligencia abierta y análisis proactivo de amenazas.
- Tecnologías y procesos de identificación, prevención, protección, respuesta y recuperación, ya que el objetivo es precisamente mejorar la detección temprana.
- Arquitectura de ciberseguridad, en caso de incluir una propuesta de integración del sistema en un entorno real. — Aunque dado que tenemos un tiempo limitado y bastante ajustado, no creo que el trabajo abarcará una pequeña parte de este punto.
- Hacking ético y Seguridad ofensiva, por el conocimiento de TTPs del adversario, fundamentales para entrenar y contextualizar modelos de detección.
- Gestión de riesgos y Estrategia de ciberseguridad, por el valor añadido del proyecto en términos de anticipación y reducción de impacto.


# Referencias

[1] https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf

[2] https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf

[3] https://www.mitre.org/sites/default/files/2021-11/prs-19-01075-28-mitre-attack-design-and-philosophy.pdf

[4] https://www.youtube.com/watch?v=Xk75Fa_YZfQ&t=2730s
