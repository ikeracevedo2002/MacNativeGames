# Plan de ejecución: de G3 abierto a TotK 1.0.0 jugable y con buen rendimiento en Windows x86-64


> Plan, no evidencia. Si contradice `GOAL.md`, `DECISIONS.md`, `PORTING_STATUS.md` o `docs/PROJECT_STATE.md`, mandan ellos. Los números de línea citados son de la revisión `a7a1fc2` y pueden desplazarse.
## Contexto

Estado (fuente: `docs/PROJECT_STATE.md`, snapshot 2026-10-22, rama `windows-x86-port`):

- G0, G1 y G2 están cerrados.
- **G3 está ABIERTO.** El loader y el enlazado están validados con los módulos reales 1.0.0. El lado SDK de `nn::init::Start` corre como código traducido. El DT_INIT de main ya está dentro de su bucle original de constructores.
  - Se admitieron 22 de los 10.539 constructores de main, cada uno con una prueba D023.
  - El cuello de botella es la iteración: cada constructor nuevo cuesta retraducir los 3 módulos, una compilación `cl` monolítica sin reutilizar `.obj` y repetir Start desde el principio.
- D024 Stage A (frontend FDE) y Stage B (catálogo no despachable + tabla de autoridad) están hechos.
  - Stage B **no se ha ejecutado nunca con datos reales**: ningún harness enlaza catálogo + tabla.
- D007 (gráficos) y D008 (backend AOT) siguen abiertos. G4–G8 no han empezado.

Objetivo final del usuario: Tears of the Kingdom corriendo en Windows x64 en el mejor estado y con el mejor rendimiento posibles. Las reglas del repo (`AGENTS.md`, `GOAL.md`) imponen orden por gates:

1. Primero cerrar G3 con un ciclo de iteración barato (D024 Stage C).
2. Después decidir D008.
3. Después G4 (Horizon headless), G5 (gráficos), G6/G7 (arranque y gameplay).
4. El rendimiento amplio va al final.

La excepción: decisiones que condicionan el rendimiento futuro (D008, modelo de memoria) se miden desde el principio.

Decisiones del usuario para este plan:

- **Ejecutor:** un agente en la máquina Windows de desarrollo con VS 18 (MSVC), LLVM, Python con `tools/aot/requirements.txt` y el directorio local 1.0.0 (`v0/`, RomFS). Todos los pasos pueden incluir ejecuciones reales.
- **Admisión de constructores:** primero se mide el coste por iteración con Stage C. Si la proyección supera el umbral, el ejecutor **redacta** un D025 candidato (admisión por lotes) y **se detiene** hasta que el usuario lo apruebe. No se implementa nada de D025 sin esa aprobación.

---

## 0. Reglas fijas para el ejecutor (aplican a todo el plan)

1. **Antes de tocar código**, leer en orden: `GOAL.md`, `DECISIONS.md` (D001–D024), `ARCHITECTURE.md`, `PORTING_PLAN.md`, `PORTING_STATUS.md`, `docs/PROJECT_STATE.md` y los fuentes Mac del subsistema afectado.
2. **Invariantes que no se tocan sin una decisión nueva aprobada por el usuario:**
   - ABI de 816 B (D010);
   - Program inmutable y transferencias por VA guest (D015);
   - llamadas anidadas host→guest (D016);
   - loader y digest de enlace (D017);
   - AS con permisos Horizon y texto guest nunca ejecutable en host (D014);
   - faults tipados y sticky;
   - monitor de exclusivas con invalidación de dominio (D013);
   - semántica FP/FPSR (D012);
   - **"compilado no es autorizado" (D024):** la `AotImage` lista solo la clausura de raíces admitidas por D021/D022/D023 y la política de símbolos vigente;
   - prueba D023 por raíz con captura en vivo obligatoria;
   - guard pre-G4 de `nnMain`.
3. **Higiene (D006):** nunca se commitea nada derivado del juego: flats, NSO, RomFS, C generado, catálogos, logs con bytes, shader caches. Todo artefacto real va a un directorio de trabajo **fuera** del repo (`<work>`). `g3_fde_emit.py` y `g3_start_prefix.py` ya rechazan salidas dentro del árbol; las herramientas nuevas también deben hacerlo.
4. **Cada cambio sustantivo debe incluir:**
   - el milestone que avanza;
   - un test o probe estrecho;
   - un **control negativo** que haría fallar una implementación incorrecta;
   - la batería completa Debug **y** Release `/W4 /WX`, con los recuentos de la §7;
   - evidencia en `DECISIONS.md` (sección de la decisión) o en `docs/`.
   - `PORTING_STATUS.md` solo se toca si cambia una condición de salida.
5. **Commits:** pequeños, uno por capacidad verificada. Formato del mensaje: `feat(windows): …` / `docs(windows): …`, como en el historial. Push a `origin windows-x86-port` (`git push -u origin windows-x86-port`, reintentos 2/4/8/16 s solo si falla la red). No abrir PR salvo que el usuario lo pida.
6. **Lo incierto se escribe como incierto.** Un resultado que solo compila no es un hito.
7. **Puntos de parada obligatorios** (marcados con 🛑 en el plan): el ejecutor redacta la propuesta, la commitea como `(candidate)` y espera la aprobación explícita del usuario antes de implementar.

---

## FASE 1 — D024 Stage C: ciclo de constructores barato (G3, PORTING_PLAN Phase 2)

Meta: que admitir un constructor nuevo deje de requerir retraducir los 3 módulos y recompilar todo, con equivalencia probada respecto al backend actual.

### Paso 1.1 — Instrumentación de tiempos en el driver (línea base)

Archivo: `tools/aot/g3_start_prefix.py`. Hoy `time` se importa pero no se usa.

1. Añadir el flag `--timing-out <path>`, que debe estar fuera del repo; validarlo con la misma comprobación que `--work` (~l.769).
2. En el bucle (`main`, ~l.883–1068), medir con `time.perf_counter()` cada fase:
   - `translate` (por módulo, dentro de `translate()`, l.470);
   - `bind` (veneer y ctor);
   - `emit_desc`;
   - `build` (separando compilación y enlace cuando exista la caché del Paso 1.3);
   - `run` (subprocess del probe);
   - `classify` (`parse_stop` + `classify_stop` + `select_follow` + prueba D023).
3. Escribir un JSON por iteración, añadido a una lista:
   `{"iteration", "backend", "roots": {"main_real": n, ...}, "t_translate": {"main_real": s, ...}, "t_bind", "t_emit_desc", "t_compile", "t_link", "t_run", "t_classify", "t_total", "c_bytes": {...}, "obj_bytes", "exe_bytes", "steps", "stop": {"code", "src", "target", "status"}, "admitted": {"kind", "va"} | null}`.
   Volcar el fichero después de **cada** iteración, para que un fallo no pierda datos.
4. Test sin datos: en `tests/aot/g3_start_prefix_test.py`, añadir un caso que llame al serializador de tiempos con valores sintéticos y compruebe esquema y claves. Negativo: una clave ausente debe hacer fallar el validador del esquema. El validador es una función nueva `validate_timing_record()` en el driver.
5. **Ejecución real (línea base):**
   ```
   python tools/aot/g3_start_prefix.py --repo <repo> --work <work>\start-c0-legacy --v0-dir <v0> \
     --python <python> --vcvars <vcvars64.bat> --max-iterations 6 [--romfs-* como en start-w21-ctor] \
     --timing-out <work>\start-c0-legacy\timing.json
   ```
   Registrar la mediana y el p90 de `t_total`, y el desglose. Es la línea base **legacy**.
6. Commit: `feat(windows): time each g3 start-prefix iteration phase`.

### Paso 1.2 — Backend "catalog" en el driver: harness real catálogo + tabla

Problema concreto (verificado en el código):

- `translate()` solo llama a `aot_translate.py`.
- `build()` (l.520) espera un único `.c` por módulo.
- `emit_desc` mapea `name → aot_image_<name>` con nombres `main_real` / `subsdk0_real` / `sdk_real`.
- El test real de Stage B usa `main` / `sdk` sin ejecutar nada.

Cambios:

1. `g3_start_prefix.py`: añadir `--backend {legacy,catalog}` (por defecto `legacy`; el comportamiento de `legacy` no cambia).
2. Una función nueva, `prepare_catalogs(repo, args, work, v0, modules)`, que se ejecuta **una vez por invocación del driver**, antes del bucle. Para cada módulo `name` (`main_real`, `subsdk0_real`, `sdk_real`):
   - Generar el manifiesto con `g3_fde_frontend.py <v0>/link/<name>.flat <v0>/link/<name>.layout.json --out <work>/cat/<name>.manifest.json --name <name> --base <hex base>`. Exit 2 o 3 es un error del driver (fail-closed).
   - Elegir la selección con `select_catalog_windows()` (Paso 1.4). Inicialmente: las ventanas FDE de las raíces ya admitidas más el lote de constructores siguiente.
   - Generar con `g3_fde_emit.py catalog --flat … --layout … --guest-base … --name <name> --manifest … --select <offs> --strict --out-c <work>/cat/<name>.cat.c --out-json <work>/cat/<name>.cat.json`.
3. Una función nueva, `translate_catalog(...)`, que sustituye a `translate()` cuando `--backend catalog`. Para cada módulo **cuyo conjunto de raíces cambió** desde la iteración anterior (guardar el hash del `entries_<name>.json` previo; los no cambiados reutilizan su tabla y su `.obj`):
   - Ejecutar `g3_fde_emit.py table --flat … --layout … --guest-base … --name <name> --entries <work>/entries_<name>.json --catalog-json … --catalog-c … --strict --out-c <work>/img/<name>.tab.c --out-json <work>/img/<name>.meta.json --report <work>/img/<name>.partition.json`.
   - Devolver `imgs[name] = [cat.c, tab.c]` y `metas[name]` = metadatos de la tabla. Son compatibles con los consumidores del driver: `source_sha256`, `unsupported` (con `body`), `local_switch_sites`, `partition`.
   - Un `PartitionMismatch` o un `REFUSED` es un error del driver, nunca un fallback silencioso a legacy.
4. Generalizar `build()` para aceptar una lista de `.c` por módulo (`images.values()` pasa a aplanarse).
5. Los consumidores de `metas[m]["unsupported"]` (rama de código 16, ~l.1032) deben resolver el estado del catálogo, que usa `CAND_PARTIAL_STATUS_BASE=0x43500000+ord` y `CAND_SWITCH_STATUS_BASE`. Añadir una función `resolve_status(metas, module, status)` que busque en `unsupported` de la tabla **y** del catálogo, y falle si encuentra 0 o más de 1 coincidencia.
6. **Coste recurrente de `verify_catalog`** (`g3_fde_emit.py` l.463): hoy regenera el catálogo completo en cada `table`. Añadir `--verify-mode {regenerate,bound}`:
   - `regenerate` (por defecto): como hoy.
   - `bound`: requiere que el SHA-256 del `.cat.c` y del `.cat.json`, la identidad (hash de herramientas, SHA del flat, base y nombre) y la selección coincidan con un recibo `<name>.cat.receipt.json`.
   - El recibo solo lo escribe el driver **tras** una verificación `regenerate` correcta en esa misma invocación.
   - Tests en `tests/aot/g3_fde_emit_test.py`, con tres negativos: un byte alterado en `.cat.c` → `REFUSED`; recibo con otra herramienta → `REFUSED`; recibo ausente → `REFUSED`.
   - Documentar en la evidencia de D024 que `bound` es un enlace por hash, no una regeneración.
7. **Puerta de equivalencia `--equivalence-check`** (nuevo flag). En cada iteración, construir y ejecutar **ambos** backends con las mismas raíces y exigir igualdad de:
   - `STARTSTOP` code, src, target y steps;
   - las 31 líneas `STARTFAULTGPR` si las hay;
   - el PC resuelto y la clase del fault.
   El `status` numérico se compara **mapeado** con `resolve_status` (namespaces disjuntos; la equivalencia es el trío fault kind, PC origen y PC resuelto, como en Stage B).
   Cualquier diferencia termina con el código 1 y un `equivalence_mismatch` en `result.json`.
8. Tests sin datos: extender `tests/aot/g3_start_prefix_test.py` con:
   - `resolve_status` (encuentra en tabla, encuentra en catálogo; 0 o 2 coincidencias → error);
   - el aplanado de listas en `build`, con un `run` simulado;
   - el detector de cambio de raíces (solo se regenera la tabla del módulo cambiado);
   - la comparación de equivalencia con dos `STARTSTOP` sintéticos que difieren en `src`, que debe fallar (negativo).
9. **Ejecución real:**
   ```
   g3_start_prefix.py … --backend catalog --equivalence-check --max-iterations 8 \
     --work <work>\start-c1-equiv --timing-out <work>\start-c1-equiv\timing.json
   ```
   Criterio: 8/8 iteraciones equivalentes y los mismos constructores admitidos, en el mismo orden, que en `start-w21-ctor`.
10. Commits:
    - `feat(windows): D024 stage C real-exec harness for catalog+table builds`;
    - `feat(windows): hash-bound catalog verification mode`.

### Paso 1.3 — Caché de objetos y enlace incremental

Archivo: `g3_start_prefix.py`, función `build()`.

1. Separar compilación y enlace: `cl /c` por TU con salida `<work>/obj/<key>.obj`, seguido de `link` (o `cl` con `.obj`) en un paso aparte. Mantener exactamente los flags actuales: `/nologo /W4 /WX /O2 /std:c11 /bigobj /D_CRT_SECURE_NO_WARNINGS`, los mismos `/I` y `bcrypt.lib`.
2. La clave de caché es el SHA-256 de:
   - los bytes del `.c`;
   - la línea de flags completa;
   - la salida de `cl` sin argumentos (versión);
   - el hash conjunto de todas las cabeceras de `src/`, `src/aot/` y `tests/aot/`, ordenadas.
   Índice en `<work>/obj/cache.json`. Un `.obj` sin entrada válida se recompila.
3. TUs estables, compiladas una vez: `CORE` (l.51), `aot_g3_start_probe.c`, `g3_start_hle.c`, `g4_romfs_start_hle.c`, `romfs_provider.c`, `romfs_file_win.c`, `host_random.c`, `romfs_start_config.c`, el descriptor y los 3 `.cat.c`. Por iteración solo cambian los `.tab.c` de los módulos cuyas raíces cambiaron, más el enlace.
4. Paralelizar la compilación de TUs pendientes con `/MP` o un pool de procesos (como máximo `os.cpu_count()`).
5. Tests sin datos:
   - clave de caché estable para entradas iguales;
   - cambia al modificar un byte de una cabecera;
   - cambia al modificar un flag (negativo: una caché que ignore cabeceras debe ser detectada por este test).
6. Ejecución real: repetir 1.2.9 con la caché activa. Registrar `t_compile` y `t_link` por separado.
7. Commit: `feat(windows): content-addressed object cache for start-prefix builds`.

### Paso 1.4 — Lote estratificado (~32 constructores y sus callees)

Nuevo módulo: `tools/aot/g3_stage_c_select.py`, importado por el driver. Expone `select_catalog_windows(manifest, ctor_targets_audit, admitted, n=32)`.

- `ctor_targets_audit` sale de `CR.Authority.targets()`, que es **solo auditoría**: sirve para elegir qué se compila, **nunca** para admitir.
- Selección:
  1. Los siguientes `n` slots de `DT_INIT_ARRAY` en orden de array tras el último admitido.
  2. Para cada uno, su ventana FDE más el cierre de BL directos cuyos destinos sean inicios FDE, acotado a una profundidad de 4 y a 512 ventanas en total.
  3. Calcular estratos por ventana: tiene BL, tiene BLR/BR (indirectos), tiene un switch D022, tiene FP/SIMD, tiene exclusivas, tiene palabras `unsupported`, o el destino no es un inicio FDE (este último se emite en la tabla, no en el catálogo).
  4. Si algún estrato queda vacío, añadir hasta 8 ventanas de constructores posteriores que lo cubran. Se marcan `purpose: "measurement"`.
- Salida: `<work>/cat/selection.json` con la lista, el estrato y el propósito de cada ventana.
- Test sin datos: un manifiesto sintético con 40 ventanas. Comprobar el orden, el cierre acotado, el relleno de estratos y que la función **no** devuelve nada marcado como raíz. Negativo: si la selección se pasa como `entries` a la tabla, el test detecta un AotImage con bloques fuera de la clausura (reusar el checker de `g3_fde_emit_test.py`).
- Commit: `feat(windows): stratified stage C catalog selection`.

### Paso 1.5 — Medición de Stage C y escalado del catálogo

1. Ejecución real:
   ```
   g3_start_prefix.py … --backend catalog --max-iterations 40 \
     --work <work>\start-c2-batch --timing-out …
   ```
   Sin `--equivalence-check`, salvo en las iteraciones 0, 10, 20 y 30, que se comprueban con el flag `--equivalence-every 10`.
2. Métricas, en el fichero nuevo `docs/evidence/stage-c-measurement.md`. Solo números y hashes, ningún byte del juego:
   - mediana y p90 de `t_total` (legacy frente a catalog);
   - tiempos de parseo y emisión del catálogo (una vez);
   - tamaño de `.c`, `.obj` y `.exe`;
   - número de palabras `unsupported` en el lote, por familia;
   - recompilaciones de catálogo evitadas por constructor nuevo: cuántas admisiones cayeron dentro del catálogo y cuántas forzaron regenerarlo;
   - cuántas ventanas del lote fueron realmente alcanzadas.
3. **Escalado (si 1.5.1 pasa la puerta):** añadir `--chunk-windows K` (por defecto 2000) a `g3_fde_emit.py catalog`.
   - Emite `<name>.cat.<i>.c`, con el array `aot_cand_catalog_<name>` en una TU índice aparte, para que MSVC no compile un único TU gigante.
   - Después, catalogar **los 10.700 destinos de constructor y sus callees** (las 3 tablas `init_array`). Medir de nuevo.
   - Referencia histórica (notas locales): todas las raíces suponían unos 68,7 MB de C, 47.437 bloques, 35 s de compilación y un PE de 18,8 MB.
   - Tests: el chunking produce el mismo conjunto de símbolos y la misma identidad que sin chunking (negativo: un bloque duplicado en dos chunks es un error de enlace detectado por el test).
4. Commit: `feat(windows): chunked catalog emission` y `docs(windows): D024 stage C measurement`.

### Paso 1.6 — Puerta de decisión Stage C → D008 🛑

Criterio de **adopción**. Deben cumplirse los tres:

- (a) 0 desigualdades en todas las comprobaciones de equivalencia;
- (b) todos los negativos existentes y nuevos rechazados, con `infra=0`;
- (c) la mediana de `t_total` por iteración baja al menos un 50 % frente a la línea base legacy del Paso 1.1.
  **Reformulado 2026-10-23 (decisión del usuario):** (c) pasa a ser el tiempo absoluto medido por
  constructor admitido, informado junto a la línea base, sin umbral del 50 %. Motivo: `run` (Start
  completo) domina y limita la mejora alcanzable; ver `docs/evidence/stage-c-measurement.md`.

Si se cumple:

1. Redactar **D008 (candidate)** en `DECISIONS.md`. Estrategia: un backend C generado offline, con un catálogo ahead-of-time por chunks a partir del frontend FDE y tablas de autoridad pequeñas.
2. Incluir los números de 1.5 y una **medida de rendimiento del código generado**: microbench de un constructor real en bucle con ns/instrucción guest, en Debug y en Release. Se necesita como entrada de la Fase 6.
3. Riesgos conocidos: el coste de las comprobaciones de AS en cada acceso; el dispatcher que vuelve al runtime en cada bloque.
4. Parar y pedir aprobación.

Si no se cumple: documentar el motivo, conservar el frontend y el manifiesto, descartar el resto y proponer alternativas, también con parada.

### Paso 1.7 — Proyección y D025 (candidate) 🛑

Con la mediana real del backend adoptado:

`proyección = mediana(t_total + t_run) × slots_restantes` (10.700 − admitidos en las 3 tablas).

- **Si la proyección es ≤ 24 h:** seguir con la Fase 2 sin D025.
- **Si es > 24 h:** redactar **D025 (candidate): admisión por lotes de slots `DT_INIT_ARRAY` ya probados.** Contenido mínimo:
  - La prueba estática D023 completa (array, RELA por slot, objetivos en TEXT del mismo módulo, CFG de DT_INIT, GOT) sigue siendo obligatoria y ya cubre todos los slots.
  - Se admiten como raíces los slots `[k, k+B)` (por ejemplo, B=256) **solo** tras una captura en vivo válida en el slot `k`.
  - Cada slot del lote se verifica **en tiempo de ejecución** por un observador del probe: en cada BLR del bucle original se comprueba `cursor-8 == slot esperado` y `target == snapshot`, leyendo por el AS verificado. Cualquier desviación es un fault tipado nuevo, `CTOR_BATCH_MISMATCH`, que invalida el lote entero.
  - El bucle guest original y sus guards no cambian. No hay bucle host de constructores. Nada se activa en runtime.
  - Negativos:
    - un slot reordenado;
    - un destino alterado tras la prueba;
    - un cursor que salta un slot;
    - un lote que cruza el final del array;
    - un lote en un módulo distinto del propietario.
  - Interacción con la prohibición de D023 ("siembra anticipada fuera de alcance"): D025 la **sustituye explícitamente** solo para lotes con verificación en vivo por slot.

Parar hasta la aprobación del usuario. Solo entonces implementar en `g3_ctor_roots.py`, el driver y `aot_g3_start_probe.c`, cada parte con sus negativos.

---

## FASE 2 — Cierre de G3 (todos los constructores reales vía código traducido)

Condición de salida de G3 (`GOAL.md`): las 10.700 entradas `init_array` (main 10.539, subsdk0 45, sdk 116) se llaman y retornan, en orden, dentro del **mismo** Start fiel (mismo proceso y mismo AS). DT_INIT de cada módulo retorna. Start llega a la frontera pre-G4 de `nnMain` (exit 2 del driver, `PRE_G4_BOUNDARY`). No se ejecuta ninguna instrucción ARM64.

### Paso 2.1 — Bucle de avance

Ejecutar el driver con el backend adoptado y `--max-iterations` alto, por ejemplo 2000 por tramo. Reanudar entre tramos con un flag nuevo `--resume-from <work>/result.json` que recargue las raíces y auditorías ya admitidas. Esas raíces se **re-prueban** con D021/D022/D023 al cargar; nunca se aceptan solo por estar en el JSON.

- Test sin datos: un `result.json` con una auditoría manipulada debe rechazarse al reanudar.

### Paso 2.2 — Manual de bloqueadores

Cada parada no-constructor se trata así. Un bloqueador equivale a un commit.

| Parada | Acción |
|---|---|
| `UNSUPPORTED_INSN` (code 16) | Añadir **una familia ISA** en `aot_translate.py` `decode()`/`emit_insn()`, con máscara exacta verificada con `llvm-mc`. Añadir escenarios diferenciales frente a Unicorn A57 en `tests/aot/g3_newfamily_diff_test.py` (o un `*_diff_test.py` nuevo por familia), con esquinas y semillas NZCV, más ≥ 1 mutante por familia. Comprobar `aot_g2_gen_identity`. La familia debe ser solo de módulo: el subset G2 debe seguir rechazándola. |
| `BAD_HLE` (thunk sin handler) | Mirar el override equivalente en Mac (`games/totk/runtime/services.c` `runtime_override` ~l.237 y sus funciones). Implementar el handler HLE **más estrecho posible** en `tests/aot/g3_start_hle.c` y moverlo a `src/` cuando G4 lo exija. Lo que en Mac solo registra (`oe::Initialize`, `pctl`, `diag`, `err`, `aoc` …) se implementa igual. Lo que tiene comportamiento real (`fs::InitializeForApplication`) requiere una decisión propia; **nunca** una respuesta de éxito falsa. |
| SVC no implementado | Portar la semántica de `services.c` / `threads.c` / `ipc.c` Mac al AS (D018/D019). Añadir un probe con testigo `VirtualQuery` y mutantes. |
| `UNTRANSLATED` fuera de la clase D023 | Aplicar las reglas existentes (STT_FUNC, D021). Si ninguna aplica, **parar** 🛑 y redactar una decisión candidata con evidencia (sitio, desensamblado, procedencia del puntero). No crear heurísticas de raíces nuevas sin aprobación. |
| Fault de memoria/permisos | Investigar con `STARTFAULTGPR`. Comparar con la semántica Mac. No relajar permisos para avanzar. |

### Paso 2.3 — Reducción proactiva de cobertura ISA (en paralelo)

Ejecutar `tools/aot/g3_coverage_report.py` y `g3_init_reach.py` sobre las 10.703 raíces, con un catálogo completo. Ordenar las familias `unsupported` por número de palabras alcanzables, de mayor a menor (Pareto). Implementar las familias de la cabeza de la lista antes de que el bucle las encuentre. Mismas reglas y tests que en la tabla anterior.

Candidatas conocidas en las notas:
- `BIC`/`MVN`;
- FP/SIMD de memoria y aritmética: `FMADD`/`FMSUB`, `FSQRT`, conversiones `FCVT*`/`SCVTF`/`UCVTF`, `FCSEL`, `FMIN`/`FMAX`, `DUP`/`INS`/`UMOV`, más formas `.4S`/`.2D`;
- `CRC32`, `PRFM` (NOP semántico), `LDPSW`, `ROR`, `LDADD`/`CAS` (LSE).

Cada familia FP amplía D012 con su matriz RN/RP/RM/RZ × DN × FZ y FPSR.

### Paso 2.4 — Cierre de G3

1. Evidencia: una ejecución completa con el recuento de entradas y retornos por slot. Añadir al probe un contador `CTOR_RET` por módulo, con su negativo: un contador que no cuente un retorno se detecta comparándolo con el tamaño del array.
2. Batería Debug y Release completa.
3. Actualizar `PORTING_STATUS.md` (fila "Module init/callbacks" a VALIDATED, G3 cerrado), `docs/PROJECT_STATE.md` y `docs/g3-module-loader.md`.
4. Pasar D021, D022 y D023 de candidate a Accepted si la revisión independiente se completó; si no, dejarlo explícito.
5. Commit: `docs(windows): close G3 with full constructor execution`.

---

## FASE 3 — G4: Horizon headless hasta un checkpoint determinista (PORTING_PLAN Phase 3)

Requisito previo 🛑: **D026 (candidate), autoridad de destinos indirectos más allá de constructores.** `nnMain` y todo el juego usan vtables y punteros a función. Sin una política, cada destino indirecto nuevo es un `UNTRANSLATED`.

El ejecutor debe:
1. Medir en el catálogo completo cuántos destinos `BLR`/`BR` hay y cuál es su procedencia: entradas de vtable en `.data.rel.ro` con RELA RELATIVE, GOT, PLT, tablas de switch.
2. Proponer una regla probada. Por ejemplo: "un destino es raíz si es el valor relocado de un slot de vtable probado (RELA RELATIVE en RO tras RELRO, alineado, inicio FDE, en TEXT del mismo módulo) **y** coincide con el valor leído en vivo en el BLR".
3. Incluir negativos y parar para aprobación.

Sin D026 aprobado no se empieza la Fase 3.

Orden de trabajo (cada punto es una tarea con probe y negativos; la referencia Mac va entre paréntesis):

1. **Despacho de SVC real.**
   - Una tabla SVC en `src/aot/` (nuevo `aot_svc.{h,c}`), sustituyendo los handlers ad hoc del harness.
   - Cablear 0x2c/0x2d, de modo que el presupuesto GetInfo 7/22 deje de cobrar alias 0.
   - Implementar 0x04/0x05 (MapMemory/UnmapMemory, con las reglas de solapamiento de stack de Mac) y 0x02/0x03.
   - (`services.c` `runtime_svc` l.245)
2. **Hilos guest y planificador.**
   - Hilos guest sobre `host_thread` (`threads.c`, 692 líneas: SVC 0x08–0x0F, 0x10–0x12, 0x16–0x1D, 0x25, 0x34, 0x35, 0x45).
   - TLR de 0x200 bytes por hilo y TPIDRRO.
   - Entrada y salida de hilo con el ABI traducido (D016): un hilo guest es un hilo host que entra con `aot_call_guest`.
   - Arbitraje de direcciones (0x34/0x35) y WaitSynchronization con un modelo correcto. Negativos: wake perdido y timeout.
   - Decisión candidata sobre el modelo de prioridad y núcleo (Mac usa QoS de pthread).
3. **Política de faults host (VEH)**: un `host_fault.{h,c}` con `AddVectoredExceptionHandler` que convierta un fault host imprevisto en un fault tipado y un volcado, sin reanudar en silencio. Probe con un acceso inválido forzado.
4. **IPC.**
   - Portar `ipc.c` (HIPC/CMIF/TIPC, `sm:`, `audren:u`) como C compartido.
   - Acotar cada conteo y descriptor contra la memoria guest.
   - Un comando desconocido devuelve un **error explícito**.
   - Material de estudio: el códec de SavageWind, con licencia MIT y su notice.
5. **Overrides de símbolos.** Portar la cadena `runtime_override` (input, font, codec, movie, time, applet, swkbd, account, fs, front, gfx) a una tabla HLE en C compartido, enlazada por nombre en el loader (los thunks D017 ya existen).
6. **FS y guardado.** Un `fs::InitializeForApplication` real sobre el proveedor RomFS (D020). Una ruta de guardado con contención y commit atómico (`fs_host.c`, `game_slot.c`), con probes de traversal, enlaces, tamaño y persistencia.
7. **Hora, account, settings, applet/oe, pctl, aoc** (sin DLC), según Mac.

**Checkpoint G4:** `nnMain` corre headless hasta la **primera llamada NVN** (`nvnBootstrapLoader` / `nvnDeviceInitialize`), interceptada por un stub que registra la llamada y detiene la ejecución de forma determinista. El log es idéntico en 3 ejecuciones (mismos SVC/IPC en el mismo orden, por hilo). Actualizar `PORTING_STATUS.md` (G4).

---

## FASE 4 — G5: gráficos (PORTING_PLAN Phase 4)

1. **Spike D007 (Vulkan primero)** 🛑. Probes con TotK real, siguiendo la §5 de `docs/research/savagewind-audit.md`:
   - tabla real de `nvnDeviceGetInteger`;
   - inventario de entry points resueltos (523 en `names.txt`) frente a los implementados;
   - tamaños y offsets de objetos con canarios;
   - vectores de formato y swizzle;
   - corpus de shaders por etapa, comparando la ruta Maxwell→SPIR-V propia (`totk_xlate` Ryujinx) con Maxwell→GLSL (SavageWind);
   - negativos de sincronización, alias y coherencia.

   Redactar D007 con evidencia y parar para aprobación.
2. **Capa NVN neutral.**
   - Separar de `hle_nvn.c` sus 23 referencias Metal detrás de una interfaz de backend: `src/gfx/nvn_backend.h`.
   - Reutilizar sin cambios los ficheros neutrales: `nvn_dirty.*`, `nvn_tex.*`, `nvn_pool_index.h`, `totk_vpool.c`, `gfx/tex/nvn_deswizzle.c`, `nvn_bcdec.c`, etc.
   - Los 523 thunks de `nvn_thunks.S` pasan a thunks HLE del Program; **no** se traduce ensamblador.
   - Los objetos NVN guardan IDs de registro, nunca punteros host en memoria guest.
3. **Backend Vulkan** en el orden de PORTING_PLAN Phase 4:
   1. dispositivo, cola y swapchain;
   2. pools de memoria guest;
   3. fences y eventos;
   4. texturas y vistas;
   5. render targets y clears;
   6. buffers;
   7. shaders;
   8. descriptores;
   9. draw y dispatch;
   10. present.

   Cada paso con un probe GPU y un negativo (por ejemplo: escritura fuera de los bytes muestreados, WaitSync sin señal, destrucción con trabajo pendiente). Preservar la lección Mac sobre la visibilidad de alias (`docs/performance-followups.md`).
4. **`totk_xlate` win-x64.** Publicación NativeAOT `win-x64` de `games/totk/tools/totk_xlate` (`Program.cs` ya genera SPIR-V para Vulkan). El servicio entrega SPIR-V y reflexión **sin** SPIRV-Cross. Hace falta un sustituto Windows de `posix_spawn` en `totk_shader_rt.m`: tuberías con `CreateProcess`, protocolo de líneas JSON idéntico. Fixtures deterministas.

**Salida G5:** clear, present, probes de vida útil y sincronización, y un shader Maxwell del juego produciendo un draw correcto.

---

## FASE 5 — G6/G7: primer arranque visible y gameplay (PORTING_PLAN Phases 5–6)

1. **Frontend Win32**: ventana, ciclo de vida y DPI (contrato de `frontend.m`).
2. **Mando**: XInput/GameInput o SDL3 (zlib), elegido en una decisión breve. Probe de entrada.
3. **Audio WASAPI**: el renderer y el mezclador (`audio_renderer.c`, `audio_mixer.c`) son C compartido; solo cambia la salida (sustituto de AudioToolbox).
4. **VP9**: `movie_host.c` con libvpx, cambiando la ruta NEON por SSE2/AVX2.
5. **swkbd y rutas de usuario, logs y caché** con `%LOCALAPPDATA%`.
6. **Semilla de shaders**: pretraducir 9.360 BNSH de 1.0.0 (`docs/first-launch-shaders.md`) y precalentar la caché de pipelines Vulkan.
7. **Checkpoints** (PORTING_PLAN Phase 6): primer frame → título → carga o partida nueva → movimiento → guardar/recargar → muerte/reintento. En cada uno se registra la última frontera buena.

**Salida G6** (UI visible, input, audio, caché reutilizada) y **G7** (checklist de gameplay sin fallbacks ocultos).

---

## FASE 6 — Rendimiento ("el mejor rendimiento") y paridad (G8)

Solo con G7 cerrado (regla de `GOAL.md` y `AGENTS.md`). Cada optimización:
- es una decisión o commit propio;
- pasa la batería de paridad diferencial completa;
- se mide con el protocolo de `docs/performance-followups.md`: 8 × 30 s A/B/B/A/B/A/A/B, p50/p95/p99, SHA del binario, misma partida, cámara y resolución.

Candidatas, en orden de impacto esperado (a confirmar con perfiles, no se asumen):

1. **Encadenamiento de bloques** dentro de la clausura admitida: llamada directa C entre bloques del mismo módulo en lugar de volver al dispatcher, preservando el PC guest y los faults.
2. **Ruta rápida de memoria guest**: traducir VA a host con una tabla de regiones y páginas guard más el VEH de la Fase 3, en lugar de la comprobación completa en cada acceso. Requiere una decisión (impacta D014) y negativos RO/OOB idénticos.
3. **Exclusivas**: un lock por granulo con striping en lugar del lock global SC (D013), con las pruebas de ABA y tamaño.
4. **FP**: ruta rápida SSE cuando FPCR está en el modo por defecto, con la ruta software para el resto (D012).
5. **Compilador**: clang-cl `-O2` frente a MSVC `/O2`, LTO y PGO sobre el código generado. Medir el tiempo de build frente al rendimiento.
6. **GPU**: caché de pipelines, compilación asíncrona, reducir barreras, y priorizar lo que ya está medido en Mac (preparación de draws, copias, memoria a largo plazo, stutter de primera compilación).
7. **Parches de juego**: portar `game_patches.c` (60 FPS, resolución de render y de salida), verificando primero los bytes originales.

**G8:** 1.4.3 (RELR, RELRO/PermissionLocked, audio REV15, parches v143; `docs/v1.4.3-port.md`), empaquetado reproducible y documentación de estabilidad en sesiones largas.

---

## 7. Verificación (aplica a cada paso)

Compilación y tests:
```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake -S <repo> -B <outside>\build -G "Visual Studio 18 2026" -A x64 -DMN_BUILD_AOT_PROOF=ON ^
  -DAOT_PYTHON=<python> -DAOT_LLVM_MC=… -DAOT_LLVM_OBJCOPY=… -DAOT_LLD=… -DAOT_LLVM_READELF=… ^
  -DMN_TOTK_V0_DIR=<v0> -DMN_TOTK_ROOTS_DIR=<roots>
cmake --build <outside>\build --config Debug -j 12 && ctest --test-dir <outside>\build -C Debug -j 6 --output-on-failure
cmake --build <outside>\build --config Release -j 12 && ctest --test-dir <outside>\build -C Release -j 6 --output-on-failure
```

Recuentos esperados:
- Hoy: 15 (AOT off), 77 (AOT on sin datos) y 82 (con `MN_TOTK_V0_DIR`).
- Cada paso que añade un test CTest sube el recuento esperado y lo anota en `docs/PROJECT_STATE.md` §5.
- Los tests Python nuevos de la Fase 1 se registran en `CMakeLists.txt` con el patrón `add_test(NAME … COMMAND "${AOT_PYTHON}" …)`, junto a `aot_g3_start_prefix_classification` (l.722) y `aot_g3_fde_emit` (l.1626).

Además:
- Regresión G2: `aot_g2_gen_identity` y los mutantes G2 12/12, que no cambian.
- Mutantes de runtime: todos rechazados, `infra=0`.
- Ejecución real de cada fase, con `result.json` y `timing.json` en `<work>`. Solo resúmenes numéricos van a `docs/evidence/`.
- Antes de cada push: `git status` limpio de artefactos del juego y `git diff --check`.

## 8. Archivos críticos (Fase 1–2)

- `tools/aot/g3_start_prefix.py`: `translate()` l.470, `emit_desc()` l.497, `build()` l.520, bucle l.883–1068, `result.json` l.1115.
- `tools/aot/g3_fde_emit.py`: `verify_catalog` l.463, `build_table` l.649, `_catalog_from_bounds` l.303, CLI l.819.
- `tools/aot/g3_fde_frontend.py` (CLI l.1110), `tools/aot/g3_ctor_roots.py` (`Authority`, `classify_site`, `bind_flat_sha`).
- Nuevo: `tools/aot/g3_stage_c_select.py`.
- Tests: `tests/aot/g3_start_prefix_test.py`, `tests/aot/g3_fde_emit_test.py`, `tests/aot/aot_g3_start_probe.c` (contador `CTOR_RET`, verificación de lotes D025 si se aprueba).
- Documentación: `DECISIONS.md` (evidencia D024, D008/D025/D026 candidate), `docs/PROJECT_STATE.md`, `PORTING_STATUS.md` (solo al cerrar G3), `docs/evidence/stage-c-measurement.md`.

## 9. Entrega nube → Windows (2026-10-23)

Hecho en la nube (Linux, sin MSVC ni datos), commits `e83551d`…`597f6bf`:

- 1.1 `--timing-out` (registro validado por iteración, incluye `t_prepare` y `t_equivalence`).
- 1.2 `--backend catalog`, `--catalog-n`, `--equivalence-every K` / `--equivalence-check`; `resolve_status`; refresco de catálogo al agotar sus siguientes constructores.
- 1.2.6 `g3_fde_emit.py table --verify-mode bound --receipt` con recibo escrito tras un `regenerate`.
- 1.3 caché de `.obj` por contenido (fuente + ruta + flags + banner de `cl` + cabeceras) y enlace separado.
- 1.4 `tools/aot/g3_stage_c_select.py` (corte en el primer slot no admitido).

Validado solo como scripts Python en Linux. **Nada de lo anterior se ha ejecutado con MSVC ni con datos.** El bucle principal del backend catalog y `run_equivalence` no tienen test hermético. Orden de validación en Windows:

1. Batería CTest Debug y Release completa; recuentos esperados 79 (AOT on sin datos) y 84 (con `MN_TOTK_V0_DIR`). Incluye `aot_g3_fde_emit` (MSVC), `aot_g3_fde_emit_receipt` y `aot_g3_stage_c_select`.
2. Línea base legacy (Paso 1.1.5) con `--timing-out`. Comprobar que imprime `BUILD compiled=N reused=0` en la iteración 0 y `reused>0` después (la caché de 1.3 se usa también en legacy).
3. Paso 1.2.9: `--backend catalog --equivalence-check --max-iterations 8`. Cualquier `equivalence_mismatch` o `REFUSED` se investiga antes de seguir; no se desactiva la puerta.
4. Paso 1.5 (medición) y la puerta 🛑 1.6.

Puntos dudosos a vigilar en la primera ejecución real: comillas de `/Fo:"…"` y `/OUT:"…"`, que `link` resuelva al de MSVC tras `vcvars`, el banner de `cl` sin argumentos usado como id del compilador, y que la caché `work/obj` no se poda (crece por iteración).
