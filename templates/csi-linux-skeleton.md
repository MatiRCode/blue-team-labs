# CyberDefenders: BlueSecOps Investigation

| Propiedad             | Detalle                                |
| :-------------------- | :------------------------------------- |
| **Plataforma**        | CyberDefenders                         |
| **Categoría**         | Blue Team / Network Forensics          |
| **Dificultad**        | Por determinar                         |
| **Estado**            | En Progreso / Bajo Investigación       |
| **Proyecto Completo** | [matircode.dev](https://matircode.dev) |

---

## 1. Resumen Ejecutivo
Proporciona una descripción de alto nivel del incidente orientada a personal directivo (C-Level). Debe resumir el vector de ataque identificado, el impacto potencial o real sobre la infraestructura y el estado actual de la mitigación sin profundizar en tecnicismos excesivos.

---

## 2. Línea de Tiempo del Incidente (Timeline)
Lista cronológica detallada de las acciones del actor de amenazas, deducidas a través del análisis del tráfico de red y los artefactos disponibles.

| Marca de Tiempo (UTC) | Evento / Acción del Atacante | Artefacto / Fuente de Log / Filtro |
| :--- | :--- | :--- |
| YYYY-MM-DD 00:00:00 | Descripción del evento inicial o actividad sospechosa detectada. | Fuente de evidencia o filtro de red utilizado |

---

## 3. Mapeo de Amenazas (MITRE ATT&CK Framework)
Correlación formal de las Tácticas, Técnicas y Procedimientos (TTPs) identificadas durante la investigación con el marco de trabajo de MITRE ATT&CK.

### Táctica: [Nombre de la Táctica, ej. Ejecución (TA0002)]
*   **Técnica:** [Nombre de la Técnica y Subtécnica, ej. Command and Scripting Interpreter: PowerShell (T1059.001)]
*   **Análisis Técnico:** Descripción analítica del comportamiento observado en los paquetes o sistemas. Se debe justificar técnicamente la asignación de la técnica basándose en los comandos, protocolos o anomalías detectadas.

---

## 4. Indicadores de Compromiso (IoCs) Encontrados
Datos tácticos extraídos del análisis que sirven para alimentar las reglas de detección en sistemas defensivos como Firewalls, EDR o SIEM.

### Indicadores de Red (Network Artifacts)
*   **Direcciones IP de C2:** IP_Direccion (Puerto de escucha)
*   **Dominios identificados:** dominio[.]com

### Indicadores de Host (Host Artifacts)
*   **Artefacto malicioso:** Nombre del archivo o recurso transferido
*   **Hash SHA-256:** Hash_Correspondiente

---

## 5. Recomendaciones de Mitigación y Erradicación
Planes de acción correctiva y preventiva sugeridos para el equipo de ingeniería con el fin de neutralizar la amenaza persistente y robustecer la postura de seguridad.

1.  Acción de contención inmediata basada en los hallazgos del tráfico.
2.  Políticas de endurecimiento (hardening) para los protocolos o servicios afectados.

---

## 6. Resolución del Desafío (CyberDefenders Q&A)
Sección técnica destinada a la resolución y validación de los requerimientos específicos del laboratorio, detallando el procedimiento analítico y la respectiva evidencia gráfica.

### Pregunta 1: [PREGUNTA]
*   **Respuesta:** `VALOR_DE_LA_FLAG_O_RESPUESTA`
*   **Metodología de Análisis:** Explicación del procedimiento técnico, herramientas empleadas (ej. Wireshark, NetworkMiner) y filtros específicos aplicados para aislar la respuesta.
  
  ![Evidencia Pregunta 1](evidence/nombre_de_la_captura_1.png)

### Pregunta 2: [PREGUNTA]
*   **Respuesta:** `VALOR_DE_LA_FLAG_O_RESPUESTA`
*   **Metodología de Análisis:** Detalle del análisis forense realizado para la extracción de la respuesta.
  
  ![Evidencia Pregunta 2](evidence/nombre_de_la_captura_2.png)