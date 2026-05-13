# Punto 7 — DevSecOps / SAST (10%)

> **Objetivo del punto:** Utilizar una herramienta de DevSecOps (SAST) open source para demostrar que detecta la vulnerabilidad identificada en la aplicación (SQL Injection).

---

## ¿Qué es SAST?

**SAST** (Static Application Security Testing) es un tipo de análisis de seguridad que revisa el **código fuente** de una aplicación sin ejecutarla. La herramienta lee el código, busca patrones que coincidan con vulnerabilidades conocidas, y genera un reporte con los hallazgos.

La idea es simple: si un desarrollador escribe código inseguro, la herramienta lo detecta **antes** de que llegue a producción. Es como un corrector ortográfico, pero para seguridad.

SAST se diferencia de DAST (Dynamic Application Security Testing) en que DAST prueba la aplicación mientras está corriendo (como hicimos con Burp Suite en el Punto 5), mientras que SAST analiza el código estático directamente.

---

## Herramienta seleccionada: Semgrep

### ¿Por qué Semgrep?

- **Open source y gratuito** — cumple con el requisito del trabajo.
- **Fácil de instalar** — se instala con `pip install semgrep`.
- **Soporta TypeScript/JavaScript** — que es el lenguaje de Juice Shop.
- **Reglas personalizables** — permite escribir reglas propias para detectar patrones específicos de la aplicación.
- **Usado en la industria** — empresas como Figma, Dropbox y Snowflake lo usan en sus pipelines de CI/CD.
- **Integración con CI/CD** — se puede integrar directamente en GitHub Actions, GitLab CI, Jenkins, etc.

---

## Ejecución del análisis

### Paso 1 — Preparación del entorno

Se clonó el repositorio de Juice Shop y se instaló Semgrep:

```bash
git clone https://github.com/juice-shop/juice-shop.git
cd juice-shop
pip install semgrep
```

### Paso 2 — Creación de reglas personalizadas

Las reglas oficiales de Semgrep requieren autenticación en el registry de Semgrep. Para este ejercicio, escribimos reglas personalizadas enfocadas específicamente en detectar SQL Injection en consultas crudas de Sequelize (la librería ORM que usa Juice Shop).

El archivo de reglas (`sqli-rules.yml`) contiene dos reglas complementarias:

```yaml
rules:
  - id: sequelize-raw-query-sql-injection
    patterns:
      - pattern-either:
          - pattern: $SEQ.query(`...${...}...`, ...)
          - pattern: $SEQ.query(`...` + $X + `...`, ...)
    message: >
      SQL Injection: Se detectó interpolación de variables dentro de una
      consulta SQL cruda de Sequelize. Los datos del usuario se están
      concatenando directamente en el string SQL, lo que permite ataques
      de SQL Injection. Se deben usar consultas parametrizadas con bind
      parameters en su lugar.
    languages: [typescript, javascript]
    severity: ERROR
    metadata:
      cwe:
        - "CWE-89: SQL Injection"
      owasp:
        - "A03:2021 - Injection"
      category: security
      confidence: HIGH
      impact: HIGH

  - id: raw-sql-template-literal-injection
    pattern-regex: "sequelize\\.query\\(`[^`]*\\$\\{[^}]*req\\.body"
    message: >
      SQL Injection Crítico: Se detectó que datos provenientes de req.body
      (entrada del usuario) se interpolan directamente en una consulta SQL.
      Esto permite a un atacante manipular la consulta y obtener acceso no
      autorizado. Usar consultas parametrizadas con bind parameters.
    languages: [typescript, javascript]
    severity: ERROR
    metadata:
      cwe:
        - "CWE-89: SQL Injection"
      owasp:
        - "A03:2021 - Injection"
      category: security
      confidence: HIGH
      impact: HIGH
```

**¿Qué hace cada regla?**

- **Regla 1 (`sequelize-raw-query-sql-injection`):** Usa análisis de patrones de Semgrep (AST-based) para detectar cualquier llamada a `.query()` donde el argumento sea un template literal con interpolación (`${...}`) o una concatenación de strings (`+`). Esto detecta el patrón vulnerable sin importar qué variable se esté interpolando.

- **Regla 2 (`raw-sql-template-literal-injection`):** Usa una expresión regular para detectar específicamente cuando lo que se interpola viene de `req.body` (es decir, datos que el usuario envió en la petición HTTP). Esta regla es más específica y confirma que la inyección proviene de entrada de usuario no sanitizada.

---

### Paso 3 — Escaneo del código VULNERABLE (antes del fix)

Se corrió Semgrep contra el directorio `routes/` de Juice Shop, que contiene toda la lógica del backend:

```bash
semgrep --config sqli-rules.yml routes/
```

**Resultado:**

```
┌─────────────────┐
│ 3 Code Findings │
└─────────────────┘

    routes/login.ts
   ❯❯❱ sequelize-raw-query-sql-injection
          ❰❰ Blocking ❱❱
          SQL Injection: Se detectó interpolación de variables dentro de
          una consulta SQL cruda de Sequelize...

           34┆ models.sequelize.query(`SELECT * FROM Users WHERE email =
               '${req.body.email || ''}' AND password =
               '${security.hash(req.body.password || '')}' AND deletedAt
               IS NULL`, { model: UserModel, plain: true })

   ❯❯❱ raw-sql-template-literal-injection
          ❰❰ Blocking ❱❱
          SQL Injection Crítico: Se detectó que datos provenientes de
          req.body se interpolan directamente en una consulta SQL...

           34┆ models.sequelize.query(`SELECT * FROM Users WHERE email =
               '${req.body.email || ''}' AND password =
               '${security.hash(req.body.password || '')}' AND deletedAt
               IS NULL`, { model: UserModel, plain: true })

    routes/search.ts
   ❯❯❱ sequelize-raw-query-sql-injection
          ❰❰ Blocking ❱❱
          SQL Injection: Se detectó interpolación de variables dentro de
          una consulta SQL cruda de Sequelize...

           23┆ models.sequelize.query(`SELECT * FROM Products WHERE
               ((name LIKE '%${criteria}%' OR description LIKE
               '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)

┌──────────────┐
│ Scan Summary │
└──────────────┘
  Findings: 3 (3 blocking)
  Rules run: 2
  Targets scanned: 61
  Ran 2 rules on 61 files: 3 findings.
```

[Evidencia: punto7_a1.png — Output de Semgrep mostrando 3 hallazgos de SQL Injection en el código vulnerable]

**Semgrep detectó 3 hallazgos en 2 archivos:**

| Archivo | Regla activada | Severidad | Línea |
|---|---|---|---|
| `routes/login.ts` | sequelize-raw-query-sql-injection | ERROR | 34 |
| `routes/login.ts` | raw-sql-template-literal-injection | ERROR | 34 |
| `routes/search.ts` | sequelize-raw-query-sql-injection | ERROR | 23 |

Ambas reglas detectaron la vulnerabilidad en `login.ts` (la que explotamos en el Punto 2). Además, Semgrep encontró **otra instancia** del mismo patrón en `routes/search.ts`, donde el campo de búsqueda de productos también es vulnerable a SQL Injection. Esto demuestra el valor de una herramienta SAST: no solo encuentra la vulnerabilidad que ya conocíamos, sino que descubre otras que podrían haber pasado desapercibidas.

---

### Paso 4 — Escaneo del código PARCHEADO (después del fix)

Se aplicó la corrección vista en el Punto 3: se reemplazó la concatenación de strings por consultas parametrizadas con `bind`.

**Código vulnerable (antes):**

```typescript
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
  { model: UserModel, plain: true }
)
```

**Código corregido (después):**

```typescript
models.sequelize.query(
  'SELECT * FROM Users WHERE email = $email AND password = $password AND deletedAt IS NULL',
  {
    bind: { email: req.body.email || '', password: security.hash(req.body.password || '') },
    model: UserModel,
    plain: true
  }
)
```

Se corrió Semgrep de nuevo contra el archivo corregido:

```bash
semgrep --config sqli-rules.yml routes/login_fixed.ts
```

**Resultado:**

```
┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
  Findings: 0 (0 blocking)
  Rules run: 2
  Targets scanned: 1
  Ran 2 rules on 1 file: 0 findings.
```

[Evidencia: punto7_a2.png — Output de Semgrep mostrando 0 hallazgos después de aplicar el fix con consultas parametrizadas]

**Cero hallazgos.** La corrección elimina completamente el patrón vulnerable. Semgrep confirma que el código parcheado ya no es susceptible a SQL Injection.

---

## ¿Cómo se integra esto en un pipeline de CI/CD?

En un entorno de desarrollo profesional, Semgrep no se corre manualmente: se integra como un paso automático en el **pipeline de CI/CD** (Continuous Integration / Continuous Deployment). Esto significa que cada vez que un desarrollador sube código nuevo (push o pull request), Semgrep corre automáticamente y:

1. **Si no encuentra hallazgos →** el pipeline continúa (build, tests, deploy).
2. **Si encuentra hallazgos de severidad ERROR →** el pipeline se **bloquea** y no permite hacer merge del código hasta que se corrija la vulnerabilidad.

**Ejemplo de integración en GitHub Actions:**

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Semgrep
        run: pip install semgrep
      - name: Run SAST
        run: semgrep --config sqli-rules.yml --error routes/
```

El flag `--error` hace que Semgrep retorne un código de error si encuentra hallazgos, lo que causa que el pipeline falle. Así, la vulnerabilidad de SQL Injection que explotamos en el Punto 2 **nunca habría llegado a producción** si este pipeline hubiera estado activo durante el desarrollo de Juice Shop.

---

## Resumen para la sustentación

> "Usamos Semgrep, una herramienta SAST open source, para escanear el código fuente de Juice Shop. Escribimos dos reglas personalizadas que detectan consultas SQL con interpolación de variables en Sequelize."
>
> "Antes del fix, Semgrep encontró 3 hallazgos de severidad ERROR en 2 archivos: `login.ts` (la vulnerabilidad que explotamos) y `search.ts` (otra instancia del mismo patrón que no conocíamos). Después de aplicar la corrección con consultas parametrizadas, Semgrep reportó 0 hallazgos."
>
> "En un entorno profesional, Semgrep se integra en el pipeline de CI/CD como un paso automático. Si detecta un patrón inseguro, bloquea el merge del código. Si este pipeline hubiera existido durante el desarrollo de Juice Shop, la SQL Injection nunca habría llegado a producción."

---

## Preguntas que nos pueden hacer

**"¿Por qué escribieron reglas propias en vez de usar las que ya trae Semgrep?"**
> Las reglas oficiales del registry de Semgrep requieren autenticación (cuenta gratuita en semgrep.dev). Escribir reglas propias demuestra que entendemos cómo funciona la herramienta a nivel técnico, no solo como usuarios. Además, en la práctica muchas organizaciones escriben reglas personalizadas para detectar patrones específicos de su stack tecnológico.

**"¿Semgrep detecta el 100% de las vulnerabilidades?"**
> No. Ninguna herramienta SAST detecta todas las vulnerabilidades. SAST tiene limitaciones inherentes: falsos negativos (vulnerabilidades que no detecta) y falsos positivos (código seguro que marca como vulnerable). Por eso en un pipeline de seguridad completo se combinan varias capas: SAST (análisis estático), DAST (pruebas dinámicas como las de Burp Suite), code review manual, y pen testing periódico.

**"¿Qué diferencia hay entre SAST y DAST?"**
> SAST analiza el código fuente sin ejecutar la aplicación. Detecta patrones vulnerables mirando cómo está escrito el código. DAST prueba la aplicación mientras está corriendo, enviando peticiones maliciosas y observando las respuestas (como hicimos con Burp Suite). SAST encuentra vulnerabilidades más temprano (en el código), DAST las confirma más tarde (en la aplicación desplegada). Son complementarios.

**"¿Qué otras herramientas SAST open source existen?"**
> Varias alternativas: **SonarQube Community Edition** (muy completo, soporta múltiples lenguajes), **NodeJsScan** (específico para Node.js), **ESLint con plugins de seguridad** (eslint-plugin-security), y **Bandit** (para Python). Elegimos Semgrep por su facilidad de uso, su soporte para TypeScript, y la posibilidad de escribir reglas personalizadas de forma intuitiva.

**"¿Qué es un pipeline de CI/CD?"**
> CI/CD significa Continuous Integration / Continuous Deployment. Es un proceso automatizado que se ejecuta cada vez que un desarrollador sube código al repositorio. El pipeline típicamente compila el código, corre los tests, ejecuta análisis de seguridad (como Semgrep), y si todo pasa, despliega la aplicación. Si algún paso falla, el pipeline se detiene y el desarrollador debe corregir antes de continuar.

**"¿Por qué Semgrep encontró una vulnerabilidad en search.ts que no habían mencionado?"**
> Ese es precisamente el valor de una herramienta SAST: encuentra vulnerabilidades que el ojo humano puede pasar por alto. Nosotros nos enfocamos en `login.ts` porque era la que explotamos, pero el mismo patrón inseguro existía en `search.ts`. En una auditoría real, habríamos parcheado ambos archivos.

**"¿Se puede evadir Semgrep?"**
> Sí, porque Semgrep busca patrones. Si un desarrollador escribe el mismo código inseguro de una forma que no coincide con el patrón de la regla (por ejemplo, guardando el query en una variable intermedia antes de pasarlo a `.query()`), Semgrep podría no detectarlo. Por eso las reglas deben ser lo más amplias posible sin generar demasiados falsos positivos, y por eso SAST no es la única línea de defensa.
