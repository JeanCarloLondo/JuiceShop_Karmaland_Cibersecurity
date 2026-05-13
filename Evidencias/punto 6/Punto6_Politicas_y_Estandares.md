# Punto 6 — Gestión de Políticas y Estándares (5%)

> **Objetivo del punto:** Identificar qué control específico de la ISO 27001 y qué estándar de la OWASP (que no sea el Top 10) aseguraría la aplicación frente a la vulnerabilidad explotada (SQL Injection), desde la perspectiva de políticas y cumplimiento.

---

## ¿Por qué importan las políticas si ya arreglamos el código?

Corregir una vulnerabilidad en el código soluciona **un caso puntual**. Pero sin políticas y estándares de por medio, nada impide que mañana otro desarrollador cometa el mismo error en otro módulo de la aplicación.

Las políticas y estándares son el marco que garantiza que la seguridad no dependa de que un desarrollador individual "se acuerde" de hacerlo bien. Son reglas organizacionales que se auditan, se miden y se hacen cumplir de forma sistemática.

Dicho de otra manera: el parche en código cura el síntoma, la política previene la enfermedad.

---

## Parte 1 — Control de ISO 27001

### ¿Qué es la ISO 27001?

La ISO 27001 es el estándar internacional para gestionar la seguridad de la información en una organización. No dice qué tecnología usar ni cómo escribir código, sino qué **controles** debe tener la organización para proteger sus activos de información. La versión vigente es la **ISO 27001:2022**.

El Anexo A de la norma define 93 controles agrupados en 4 categorías: organizacionales, de personas, físicos y tecnológicos. Cada control tiene un identificador y un objetivo claro.

---

### Control aplicable: A.8.28 — Codificación Segura

**Categoría:** Controles tecnológicos

**Qué establece:** La organización debe definir y aplicar principios de codificación segura en el desarrollo de software. Esto incluye:

- Establecer requisitos mínimos de seguridad antes de empezar a escribir código.
- Seguir prácticas de codificación que prevengan vulnerabilidades conocidas.
- Revisar el código para verificar que se aplicaron dichos principios.
- Usar herramientas automatizadas para detectar defectos de seguridad en el código.

**¿Cómo previene la SQL Injection?**

Si Juice Shop hubiera sido desarrollado bajo una política que implementara el control A.8.28, los principios de codificación segura habrían incluido como requisito obligatorio el uso de **consultas parametrizadas** para toda interacción con la base de datos. El desarrollador que escribió el login con concatenación de strings (`${req.body.email}` directo en el SQL) habría incumplido la política, y esto se habría detectado en la revisión de código o con una herramienta SAST antes de llegar a producción.

La vulnerabilidad que explotamos existe precisamente porque no había una política que exigiera codificación segura. El código se escribió de la forma más rápida (concatenando), no de la forma más segura (parametrizando).

---

### Control complementario: A.8.25 — Ciclo de Vida de Desarrollo Seguro

**Categoría:** Controles tecnológicos

**Qué establece:** La organización debe definir reglas para el desarrollo seguro de software y sistemas, aplicándolas a todo el ciclo de vida: diseño, codificación, pruebas y despliegue.

**¿Cómo complementa al A.8.28?**

Mientras que A.8.28 se enfoca específicamente en **cómo se escribe el código**, A.8.25 abarca todo el ciclo: que haya revisión de seguridad en el diseño, que se hagan pruebas de seguridad antes de desplegar, que se integren herramientas de análisis estático (SAST) en el pipeline de CI/CD. Es el control que convierte la seguridad en un proceso continuo, no en algo que se revisa al final.

Juntos, A.8.25 y A.8.28 forman la base de lo que en la industria se conoce como **Secure SDLC** (ciclo de vida de desarrollo seguro).

---

## Parte 2 — Estándar OWASP (No Top 10)

### ¿Por qué no usamos el OWASP Top 10?

El OWASP Top 10 es un **documento de concientización**: lista las 10 categorías de riesgos más críticos en aplicaciones web para que las organizaciones sepan qué priorizar. Pero no define requisitos verificables, no tiene niveles de madurez y no sirve como checklist de auditoría. Es un punto de partida, no un estándar de cumplimiento.

Para este punto necesitamos algo más concreto: un estándar que diga exactamente **qué debe cumplir la aplicación** y cómo verificarlo.

---

### Estándar seleccionado: OWASP ASVS (Application Security Verification Standard)

**Versión:** 4.0.3

**¿Qué es el ASVS?**

El ASVS es un estándar de verificación de seguridad para aplicaciones web. Define una lista exhaustiva de **requisitos técnicos de seguridad** que una aplicación debería cumplir, organizados en 14 categorías (autenticación, sesiones, control de acceso, validación de entradas, criptografía, etc.).

A diferencia del Top 10 (que dice "ojo con las inyecciones"), el ASVS dice exactamente **qué tiene que hacer la aplicación** para estar protegida, y permite verificarlo de forma objetiva.

**¿Por qué elegimos este estándar?**

1. **Es verificable:** cada requisito está redactado de forma que se puede comprobar con un "sí cumple" o "no cumple". Esto lo hace ideal para auditorías.
2. **Es específico:** tiene requisitos concretos contra SQL Injection, no solo recomendaciones generales.
3. **Tiene niveles de madurez:** define tres niveles (L1, L2, L3) según la criticidad de la aplicación, lo que permite adaptar el rigor de la verificación.
4. **Es complementario a la ISO 27001:** el control A.8.28 dice "aplique principios de codificación segura", y el ASVS define cuáles son esos principios para aplicaciones web.

---

### Requisito específico aplicable

**Sección:** V5 — Validation, Sanitization and Encoding

**Requisito:** V5.3.4

**Qué dice:** *"Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks."*

**Traducido:** La aplicación debe usar consultas parametrizadas, ORMs o frameworks de entidades para toda interacción con la base de datos. No se permite la concatenación directa de datos del usuario en las consultas.

**Nivel:** L1 (requerido incluso para el nivel más básico de verificación).

**¿Cómo previene la SQL Injection?**

Este requisito es directo y sin ambigüedad: si la organización adoptara ASVS como estándar y verificara el cumplimiento del requisito V5.3.4, el código vulnerable de Juice Shop (`SELECT * FROM Users WHERE email = '${req.body.email}'`) habría sido marcado como **no conforme** inmediatamente. La corrección que implementamos en el Punto 3 (usar `bind` con placeholders en Sequelize) es exactamente lo que este requisito exige.

---

### Requisito complementario

**Requisito:** V5.3.5

**Qué dice:** *"Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks."*

**Traducido:** Si por alguna razón no se pueden usar consultas parametrizadas (caso raro, pero posible en consultas dinámicas muy complejas), la aplicación debe aplicar encoding específico al contexto para neutralizar los caracteres peligrosos.

Esto refuerza la idea de que la protección contra inyecciones no es opcional bajo ninguna circunstancia: o parametrizas, o encodeas. No hay un tercer camino.

---

## ¿Cómo se conectan la ISO 27001 y el ASVS?

La relación entre ambos es jerárquica y complementaria:

```
ISO 27001 (Nivel organizacional)
    └── Control A.8.28: "La organización debe aplicar principios de codificación segura"
            └── ¿Cuáles principios? Los define el ASVS (Nivel técnico)
                    └── Requisito V5.3.4: "Usar consultas parametrizadas"
                            └── Implementación: bind parameters en Sequelize (Nivel de código)
```

La ISO 27001 establece la **política** ("debemos codificar de forma segura"). El ASVS traduce esa política en **requisitos técnicos verificables** ("toda consulta a base de datos debe ser parametrizada"). Y la implementación en código es la **evidencia de cumplimiento** (el `bind` que aplicamos en el Punto 3).

Sin la política, nadie exige que el código sea seguro. Sin el estándar técnico, la política es vaga e inauditable. Sin la implementación, todo queda en papel. Las tres capas son necesarias.

---

## Resumen para la sustentación

> "Desde la perspectiva de políticas y cumplimiento, la vulnerabilidad de SQL Injection que explotamos se habría prevenido con dos marcos normativos."
>
> "Primero, el control **A.8.28 de la ISO 27001:2022** (Codificación Segura), que exige que la organización defina y aplique principios de codificación segura en el desarrollo de software. Si existiera esta política, el uso de consultas parametrizadas sería un requisito obligatorio, no una decisión del desarrollador individual."
>
> "Segundo, el estándar **OWASP ASVS** (Application Security Verification Standard), específicamente el requisito **V5.3.4**, que establece explícitamente que toda consulta a base de datos debe usar consultas parametrizadas, ORMs o mecanismos equivalentes. Este requisito es de nivel L1, lo que significa que aplica incluso para el nivel más básico de verificación de seguridad."
>
> "No usamos el OWASP Top 10 porque es un documento de concientización que lista riesgos generales, no un estándar con requisitos verificables. El ASVS, en cambio, define requisitos concretos que se pueden auditar: ¿la consulta está parametrizada? Sí o no. Eso lo hace adecuado para cumplimiento."
>
> "La ISO 27001 dice *qué* hay que hacer (codificar de forma segura). El ASVS dice *cómo* verificarlo (consultas parametrizadas). Y el código que implementamos en el Punto 3 es la evidencia de que se cumple."

---

## Preguntas que nos pueden hacer

**"¿Por qué ASVS y no OWASP SAMM?"**
> SAMM (Software Assurance Maturity Model) mide la madurez del programa de seguridad de una organización: sus procesos, su governance, su cultura. Es valioso, pero no define requisitos técnicos para la aplicación. ASVS define requisitos concretos y verificables a nivel de código y funcionalidad. Para una vulnerabilidad específica como SQL Injection, ASVS es el estándar que aplica directamente.

**"¿Por qué ASVS y no el OWASP Testing Guide?"**
> El Testing Guide (WSTG) dice *cómo probar* si una vulnerabilidad existe: qué herramientas usar, qué payloads probar, cómo interpretar los resultados. El ASVS dice *qué requisitos debe cumplir* la aplicación. Son complementarios: el ASVS define el "qué" y el Testing Guide define el "cómo verificarlo". Para este punto, que pide políticas y cumplimiento, el ASVS es el que establece la regla.

**"¿La ISO 27001 obliga a usar ASVS?"**
> No directamente. La ISO 27001 dice que hay que aplicar principios de codificación segura, pero no prescribe qué estándar técnico usar. La organización elige. Nosotros elegimos ASVS porque es el estándar más reconocido y completo para verificación de seguridad en aplicaciones web, y porque está desarrollado por OWASP, la misma comunidad que creó Juice Shop.

**"¿Qué pasa si una organización tiene ISO 27001 pero no implementa el control A.8.28?"**
> La ISO 27001:2022 permite excluir controles del Anexo A si se justifica que no aplican al contexto de la organización (mediante la Declaración de Aplicabilidad). Pero para una organización que desarrolla software, excluir el A.8.28 sería difícil de justificar ante un auditor, especialmente si ya ha sufrido incidentes de seguridad en sus aplicaciones.

**"¿Qué nivel de ASVS le aplicarían a Juice Shop?"**
> Depende del contexto. Si Juice Shop fuera una tienda real con datos de clientes y pagos, le aplicaríamos al menos **Nivel 2** (para aplicaciones que manejan datos sensibles). El Nivel 1 cubre lo básico y ya incluye el requisito V5.3.4 de consultas parametrizadas. El Nivel 3 es para aplicaciones críticas como banca o salud.

**"¿Cómo se audita el cumplimiento de V5.3.4 en la práctica?"**
> Se audita con una combinación de revisión de código (manual o con herramientas SAST como Semgrep, que usaremos en el Punto 7) y pruebas de penetración (intentar inyectar SQL y verificar que no funciona, como hicimos en el Punto 2 antes y después del parche). Si la herramienta SAST no detecta concatenación en consultas SQL y las pruebas de penetración confirman que la inyección no es posible, el requisito se marca como cumplido.
