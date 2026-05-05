# Punto 5 — Herramienta Defensiva (10%)

> **Objetivo del punto:** Demostrar cómo se ve reflejado el ataque en la red usando una herramienta de monitoreo, y proponer una herramienta del Blue Team para monitorear y generar alertas frente a este tipo de ataque.

---

## 5A — Análisis del ataque en la red

### Herramienta utilizada: Burp Suite Community Edition

Burp Suite es un proxy de interceptación HTTP, ampliamente usado en ciberseguridad para analizar el tráfico entre un navegador y un servidor web. Se coloca "en el medio": el navegador le envía las peticiones a Burp, Burp las registra y las reenvía al servidor, y hace lo mismo con las respuestas.

Para este ejercicio usamos el módulo **Repeater**, que permite reenviar una petición al servidor y ver la respuesta de forma clara, lado a lado. Esto nos permitió comparar dos escenarios sobre el mismo endpoint de login (`POST /rest/user/login`).

### Configuración del entorno

- **Juice Shop** corriendo en local con Docker (`docker run -d -p 3000:3000 bkimminich/juice-shop`), accesible en `http://localhost:3000`.
- **Burp Suite** escuchando en `127.0.0.1:8080` como proxy HTTP.
- **Firefox** configurado con proxy manual apuntando a `127.0.0.1:8080`.
- En Firefox, se habilitó `network.proxy.allow_hijacking_localhost = true` en `about:config` para que el tráfico a localhost también pase por el proxy.

---

### Escenario 1 — Login legítimo (fallido)

Se envió una petición de login con credenciales normales (un email y un password cualquiera) para establecer una línea base del comportamiento esperado del servidor.

**Petición:**

```json
{
    "email": "test@test.com",
    "password": "123456"
}
```

**Respuesta del servidor:**

```
HTTP/1.1 401 Unauthorized
```
```
Invalid email or password.
```

El servidor verificó las credenciales, no encontró coincidencia, y rechazó el acceso. Este es el comportamiento correcto y esperado.

[Evidencia: punto5_a1.png — Página de login de Juice Shop mostrando el mensaje "Invalid email or password"]

[Evidencia: punto5_a2.png — Burp Suite Repeater mostrando la petición con credenciales normales y la respuesta 401 Unauthorized]

---

### Escenario 2 — Ataque de SQL Injection

Se envió una petición de login con un payload de SQL Injection en el campo de email. En lugar de un correo electrónico, se introdujo una instrucción SQL diseñada para alterar la lógica de la consulta en la base de datos.

**Petición:**

```json
{
    "email": "' OR 1=1--",
    "password": "x"
}
```

**Respuesta del servidor:**

```
HTTP/1.1 200 OK
```
```json
{
    "authentication": {
        "token": "eyJhbGciOiJSUzI1NiJ9...",
        "bid": 1,
        "umail": "admin@juice-sh.op"
    }
}
```

El servidor respondió **200 OK** y devolvió un token de sesión válido junto con los datos del usuario administrador (`admin@juice-sh.op`). Sin conocer la contraseña, el atacante obtuvo acceso completo al sistema con privilegios de administrador.

[Evidencia: punto5_a3.png — Burp Suite Repeater mostrando la petición con payload de SQL Injection y la respuesta 200 OK con token de administrador]

---

### ¿Qué demuestra esta comparación?

La diferencia entre ambos escenarios es evidente al inspeccionar el tráfico:

| Aspecto | Login legítimo | SQL Injection |
|---|---|---|
| Contenido del campo email | `test@test.com` | `' OR 1=1--` |
| Caracteres sospechosos | Ninguno | Comilla simple `'`, operador `OR`, comentario `--` |
| Código de respuesta | 401 Unauthorized | 200 OK |
| Resultado | Acceso denegado | Token de admin entregado |

Un campo de email legítimo nunca contiene comillas simples, operadores SQL ni comentarios de base de datos. Cualquier sistema de monitoreo que inspeccione el contenido de las peticiones HTTP podría detectar estos patrones como anómalos y generar una alerta.

---

## 5B — Herramienta Blue Team para monitoreo y alertas

### Enfoque propuesto: defensa en dos capas

Para proteger una aplicación como Juice Shop en producción contra ataques de SQL Injection, proponemos dos capas complementarias: una de **prevención** y otra de **detección y respuesta**.

---

### Capa 1 — Prevención: AWS WAF

Un **WAF** (Web Application Firewall) es un firewall especializado en tráfico web. A diferencia de un firewall tradicional que filtra por IP o puerto, el WAF inspecciona el **contenido** de las peticiones HTTP: headers, URL, body, cookies.

**AWS WAF** se integra directamente con servicios de AWS como el Application Load Balancer (ALB). Se coloca **delante** de la aplicación y evalúa cada petición antes de dejarla pasar.

AWS WAF incluye un grupo de reglas administradas llamado **`AWSManagedRulesSQLiRuleSet`**, diseñado específicamente para detectar patrones de SQL Injection. Si un atacante manda `' OR 1=1--` en cualquier campo del body o la URL, el WAF **bloquea la petición** y esta nunca llega al servidor.

**Flujo con WAF:**

```
Usuario → AWS WAF → Application Load Balancer → EC2 (Juice Shop)
              ↓
     Petición bloqueada
     (si detecta SQL Injection)
```

El WAF actúa como un filtro inteligente en la puerta: revisa lo que trae cada petición antes de dejarla pasar al servidor.

---

### Capa 2 — Detección y alertas: AWS CloudWatch + SNS

El WAF no solo bloquea: también **registra todo** lo que hace. Cada petición evaluada (bloqueada o permitida) genera un log con detalles como la IP de origen, el payload detectado, la regla que se activó y la acción tomada.

Esos logs se envían a **AWS CloudWatch**, donde podemos:

1. **Crear una métrica personalizada** que cuente cuántas peticiones fueron bloqueadas por reglas de SQL Injection en un período de tiempo.
2. **Configurar una alarma** que se dispare cuando se supere un umbral definido (por ejemplo, más de 5 intentos de inyección en 1 minuto desde la misma IP).
3. **Enviar una notificación automática** al equipo de seguridad a través de **AWS SNS** (Simple Notification Service), que puede entregar alertas por email, SMS o integración con Slack.

Esto permite **respuesta en tiempo real**: si alguien está probando inyecciones contra la aplicación, el equipo de seguridad se entera inmediatamente, no semanas después revisando logs.

---

### Alternativa Open Source: Wazuh

Para organizaciones que no usan AWS o prefieren herramientas open source, **Wazuh** es un **SIEM** (Security Information and Event Management) que cumple un rol similar:

- **Recolecta logs** del servidor web (access logs de Express/Node.js en este caso) y los centraliza.
- Tiene **reglas predefinidas** que detectan patrones de SQL Injection en los logs: comillas simples, `UNION SELECT`, `OR 1=1`, `DROP TABLE`, etc.
- Genera **alertas en tiempo real** cuando detecta actividad sospechosa.
- Ofrece un **dashboard visual** (basado en OpenSearch/Kibana) para analizar tendencias y responder a incidentes.
- Es **gratuito y open source**, lo cual lo hace accesible para cualquier organización sin importar su presupuesto.

---

### ¿El WAF reemplaza la corrección en el código?

**No.** El WAF es una capa de **defensa en profundidad**, no un sustituto de la corrección en código.

Un atacante sofisticado puede intentar evadir el WAF con técnicas como:

- Codificar los caracteres en hexadecimal o URL encoding.
- Usar variaciones del SQL que el WAF no reconozca.
- Fragmentar el payload en múltiples peticiones.

La protección fundamental siempre es el **código seguro**: consultas parametrizadas (como la que implementamos en el Punto 3), validación de entradas, y principio de menor privilegio en la base de datos. El WAF es un escudo adicional, pero la armadura real está en el código.

La filosofía correcta es: **corrige el código Y pon un WAF**. Nunca uno sin el otro.

---

## Resumen para la sustentación

> "Capturamos el tráfico del ataque usando Burp Suite como proxy de interceptación. Comparamos una petición de login legítima (que devuelve 401 Unauthorized) contra una con payload de SQL Injection (que devuelve 200 OK con token de administrador). La inyección es completamente visible en el tráfico HTTP: el campo email contiene caracteres que jamás estarían en un correo real."
>
> "Para monitorear y prevenir este tipo de ataque en producción, proponemos dos capas: primero, un AWS WAF con las reglas `AWSManagedRulesSQLiRuleSet` activadas, que bloquea las peticiones maliciosas antes de que lleguen a la aplicación. Segundo, los logs del WAF se envían a CloudWatch donde configuramos alarmas que notifican al equipo de seguridad a través de SNS cuando se detectan múltiples intentos de inyección. Como alternativa open source, Wazuh ofrece capacidades equivalentes de SIEM con detección de SQLi y alertas en tiempo real."
>
> "El WAF no reemplaza la corrección en código. Es defensa en profundidad: si una capa falla, las demás sostienen la seguridad."

---

## Preguntas que nos pueden hacer

**"¿Por qué Burp Suite y no Wireshark?"**
> Burp Suite está diseñado para tráfico HTTP: parsea las peticiones y respuestas automáticamente y las muestra de forma legible. Wireshark captura todo el tráfico de red a nivel de paquetes (TCP, UDP, DNS, etc.), lo cual es más potente pero también más ruidoso para analizar un ataque web puntual. Para demostrar un ataque contra una API REST, Burp es la herramienta más adecuada.

**"¿Qué pasa si el atacante usa HTTPS? ¿Burp igual lo ve?"**
> Sí. Burp actúa como proxy de interceptación: el navegador envía el tráfico cifrado a Burp, Burp lo descifra con su propio certificado, lo muestra al analista, y lo reenvía cifrado al servidor. Lo mismo ocurre con el WAF en producción: descifra el TLS antes de inspeccionar el contenido de la petición.

**"¿CloudWatch puede detectar SQL Injection sin WAF?"**
> Podría, pero sería mucho más difícil. CloudWatch trabaja con logs y métricas. Si los logs de la aplicación registran los payloads de las peticiones, se podrían crear filtros que busquen patrones sospechosos. Pero el WAF lo hace de forma nativa y especializada. CloudWatch se usa mejor como complemento para agregar los logs del WAF y generar alertas.

**"¿Cuánto cuesta implementar esto en AWS?"**
> AWS WAF cobra por reglas activas (aprox. $5/mes por grupo de reglas) y por millón de peticiones evaluadas ($0.60). Para una aplicación del tamaño de Juice Shop, el costo es mínimo: unos pocos dólares al mes. CloudWatch tiene un nivel gratuito generoso. La inversión en seguridad es insignificante comparada con el costo potencial de una brecha de datos.

**"¿Qué es un SIEM?"**
> SIEM significa Security Information and Event Management. Es un sistema que centraliza los logs de múltiples fuentes (servidores, firewalls, WAFs, aplicaciones), los correlaciona, y genera alertas cuando detecta patrones sospechosos. Wazuh es un SIEM open source. Alternativas comerciales incluyen Splunk, IBM QRadar y Microsoft Sentinel.

**"Si Burp Suite puede hacer este ataque, ¿es una herramienta de hackers?"**
> Burp Suite es una herramienta de seguridad ofensiva legítima, usada por profesionales de ciberseguridad, pentesters y equipos de Red Team para evaluar la seguridad de aplicaciones web de forma autorizada. La misma herramienta que se usa para encontrar vulnerabilidades es la que se usa para demostrar que existen y justificar su corrección. Lo ilegal no es la herramienta, es usarla sin autorización contra sistemas ajenos.
