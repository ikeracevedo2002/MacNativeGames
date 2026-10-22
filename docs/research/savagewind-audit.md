# Auditoría de SavageWindRecomp para el port Windows de TOTK

## Dictamen

**Recomiendo adoptar y endurecer partes del frontend y del modelo de generación/build de SavageWind, no sustituir nuestro runtime por el suyo.** Su generación AOT por módulos proporciona una alternativa concreta al ciclo de recompilar tras cada nueva función alcanzada. Su ABI, memoria, exclusivas y tratamiento de errores, en cambio, no preservan varias garantías que ya hemos validado.

Es un **cambio acotado de estrategia de generación**, sujeto a un experimento comparativo, no autorización para nuevas roots. Compilar una función anticipadamente no puede conferir permiso para ejecutarla.

Para gráficos, Vulkan pasa a ser el primer candidato que merece un spike basado en código existente. No hay evidencia suficiente para cerrar D007 ni para prometer un porcentaje de reutilización. Para CPU, la generación C es la primera alternativa a medir bajo nuestro ABI; el rendimiento de BOTW no cierra D008 para TOTK.

Esta auditoría no cambia código, `DECISIONS.md` ni `PORTING_STATUS.md`. No integra worktrees ni genera C del juego. El único archivo añadido al checkout principal es este informe.

## 1. Alcance, fuentes y estado comparado

Fuente principal: [`ikeracevedo2002/SavageWindRecomp`](https://github.com/ikeracevedo2002/SavageWindRecomp), fijada en **`575ad88e02f9a89a9a885d90039d48af33c982f4`**. Las referencias SW de este informe apuntan a ese commit, no a `main` mutable. Se inspeccionaron herramientas, runtime, Windows/POSIX, servicios, FS, NVN, Vulkan, Maxwell, scripts y licencias. Hubo revisión independiente de CPU, servicios y gráficos, seguida de contraste arquitectónico.

Comparación local:

- Checkout `windows-x86-port`, HEAD `d3b45204`, y candidato **no integrado** `w21-2`.
- G2: backend BB-C y contrato explícito del estado guest.
- G3: loader validado, memoria guest separada de host, permisos, exclusivas con invalidación de dominio, FP software, control de llamadas/retornos y fallos tipados.
- D023 en el candidato: admisión estricta de constructores por metadata y contexto del loop original. No equivale a autorizar targets arbitrarios de BLR.
- El candidato conserva 78/78 tests Debug y Release de su validación anterior. **No se repitió esa batería durante esta auditoría documental.**

El ensayo `start-w21-ctor` llegó a 22 constructores retornados y admitió una entrada adicional pendiente de regeneración. Finalizó por el límite de 24 iteraciones. El intento de ampliar el presupuesto se interrumpió al pedir el usuario pausar código. No es evidencia de un nuevo bloqueo del traductor ni de constructores completos.

Snapshot del candidato inspeccionado:

- `tools/aot/g3_ctor_roots.py`: SHA-256 `118f08e08c46a8bb2875043cfe1bdbea71ed9916d38798b6c720f8ceb92eecc1`.
- `tools/aot/aot_translate.py`: SHA-256 `10bac5d5a94c05885b776bb3b1b3b716bba8b0bea1c9d96db9d792c2101172a1`.

### Comprobaciones realizadas durante la auditoría

Todas fueron análisis offline de herramientas existentes; sin emitir código AOT de TOTK ni ejecutar un runtime alternativo:

1. `tools/test_layout.py` de SW: **55/55 checks**.
2. Lectura de nuestros NSO originales mediante `tools/nso.py` de SW.
3. Lectura FDE y discovery de `analyze.py`.
4. Ejecución del método real **`gen.Module.boundaries()`** sobre los tres módulos. Esto no es el fixpoint completo `gen.discover()`, ni generación, compilación o ejecución.
5. Validación estructural de las tres tablas usando **nuestro** `g3_ctor_roots.derive()` existente. No activa roots ni prueba el cursor de una llamada concreta.
6. Desensamblado del chequeo NVN original de TOTK.

| Módulo | FDE encontrados | Entradas DT_INIT_ARRAY | Targets en inicio FDE | Boundaries iniciales de `gen.py` | Targets presentes en esos boundaries |
|---|---:|---:|---:|---:|---:|
| main | 242 860 | 10 539 | 10 539 | 242 863 | 10 539 |
| subsdk0 | 10 061 | 45 | 45 | 10 078 | 45 |
| sdk | 31 238 | 116 | 116 | 31 282 | 116 |
| Total | 284 159 | **10 700** | **10 700** | 284 223 | **10 700** |

Nuestro validador estructural también acepta los rangos completos de esas tres tablas. El constructor inicial de main, `0x1520`, coincide con un inicio FDE, rango `[0x1520, 0x1584)`.

**Qué demuestra:** compatibilidad real de metadata y que no necesitamos descubrir cada constructor por una nueva heurística de BLR.

**Qué no demuestra:** cobertura del lifter, límites correctos de todas las funciones, distinción completa código/datos, ABI equivalente, ejecución correcta, orden de inicialización o arranque de TOTK. FDE es evidencia adicional, no autoridad universal. El método antiguo `analyze.discover_functions()` y el generador actual tampoco producen necesariamente el mismo conjunto de candidatos.

Evidencia local, fuera del árbol: `C:\Users\IKER\mn-research\sw-totk-metadata-probe.json`, `sw-totk-generator-boundaries.json`, `mn-ctor-structural-audit.json`, `sw-layout-test.log`, `totk-nvn-version-guard.txt`. No se incorporan módulos, tablas extraídas ni código del juego al repositorio.

## 2. Matriz de reutilización

ADOPT significa candidato concreto a incorporar **tras la adaptación y sus tests**, no código ya aprobado o integrado.

| Área | Nuestra solución | SavageWind | Compatibilidad esperada | Recomendación |
|---|---|---|---|---|
| Discovery NSO/FDE | CFG/manifest parcial, metadata validada | FDE/símbolos/relocs y partición | Alta en metadata: 10 700/10 700 ctors | **ADOPT parcial**, endurecer parser. [S2], [S3] |
| Generación/build | BB-C del subconjunto alcanzado | Módulos completos, chunks, `swgame.dll` | Concepto trasladable; coste con nuestro ABI desconocido | **ADOPT concepto / STUDY implementación**. [S4], [S5] |
| Código/datos y roots | Root classes conservadoras, known-DATA | Scans BL/ADR/ADRP y RELATIVE más amplios | No como autoridad de ejecución | **KEEP OURS**; scans sólo candidatos. [S4] |
| Lifter escalar/SIMD | Cobertura incremental con oráculos/negativos | Cobertura amplia, C/asm, traps si no soportado | Operaciones puras sí; memoria/control no drop-in | **ADAPT selectivo**. [S6], [S7] |
| ABI y callbacks | Estado 816 B; Program, guest VA | Cpu 1024 B; llamadas C/dispatch | Incompatible directamente | **KEEP OURS**. [S8], [S9] |
| Memoria/fallos | VA separado, permisos y fallos tipados | Guest==host, autocommit | Incompatible | **DO NOT COPY** esos supuestos. [S8], [S10] |
| Exclusivas/FP | Invalidación de dominio, FP/FPSR software | CAS por valor; FPSR/QC limitado | No satisface nuestro contrato en esos aspectos | **KEEP OURS**. [S7], [S8] |
| Loader/linker | Rangos/SHA, precedencia, 558 865 relocs contrastadas | Build ID, RELA/JMPREL/RELR, GNU hash | Formatos comunes; errores y semántica difieren | **KEEP OURS**, adoptar fixtures. [S11] |
| Init/fini | Loop guest, D023, referencia Mac | DT_INIT/FINI, fallback arrays, orden SDK propio | Discovery sí; orden completo TOTK no probado | **ADAPT discovery**, conservar ejecución. [S12] |
| SVC/threads | Abstracciones estrechas, aliases reales | Kernel host más amplio, varias aproximaciones | Evaluar por operación, no runtime entero | **STUDY**, no copiar stubs. [S13] |
| IPC/servicios | G4 pendiente sobre memoria validada | HIPC/CMIF/TIPC y 21 nombres de servicio | Protocolos/handlers seleccionados, no buffers raw | **ADAPT** con límites/errores. [S14] |
| RomFS/save/overlays | Provider inmutable y Win32 fuera del core | Storage IPC, imagen RomFS, overlays y FS host | IPC útil; saves/version patches no drop-in | **KEEP provider / STUDY IPC**. [S15] |
| NVN | Referencia Mac, Windows pendiente | 55.15 y wrappers de BOTW | Versión compatible; ABI de objetos abierto | **STUDY + probe ABI**. [S16] |
| Vulkan | D007 abierta | Device/resources/pipelines/exec existentes | Potencial sustancial con adaptación | **ADAPT tras spike**, no copiar sync/VA. [S17], [S18] |
| Maxwell/shaders | Maxwell→SPIR-V existente | Maxwell→GLSL→shaderc→SPIR-V | ISA común; corpus/etapas TOTK no probados | **STUDY/ADAPT alternativa**. [S19] |
| Licencias/package | Runtime propio y datos fuera del árbol | MIT propio + dependencias y helper GPL | Código propio reutilizable; paquete no homogéneo MIT | **ADOPT con notices; auditar terceros**. [S20], [S21] |

### ADOPT

- Frontend de metadata y lector FDE endurecido; builder de NSO sintético de `test_layout.py`.
- Organización por chunks, cuerpos estables e identidad de build, adaptada a nuestro ABI.
- Helpers puros del lifter cuando superen equivalencia y negativos; no importar todo el emisor de memoria/control.

### STUDY

- `nn::init::Start`, TLS, HIPC/CMIF/TIPC, comandos y wrappers de SDK antes de implementar sus equivalentes.
- Contrato NVN 55.15, Vulkan y Maxwell como referencias concretas para los spikes de G5.
- Fallbacks/heurísticas y tests upstream como corpus, no prueba de corrección para TOTK.

### KEEP OURS

ABI/Program, guest VA, loader validado, permisos, fallos, exclusivas, FP/FPSR, llamadas anidadas y provider RomFS inmutable.

### DO NOT COPY

Identidad guest-host, autocommit, punteros host en objetos guest, CAS-exclusivas, RET como simple retorno C, fallback all-labels como autoridad, éxito para HLE desconocido, orden/init-array host no probado, saves sin contención/commit, parches de versión/frame-loop de BOTW y aproximaciones GPU.

## 3. CPU AOT: qué hace realmente y qué no podemos importar

### Discovery y salida

SW convierte NSO en C por funciones, distribuye cuerpos en chunks y enlaza una biblioteca del juego. Usa FDE, símbolos, punteros relocados y scans de instrucciones para proponer límites. El fixpoint subdivide al descubrir destinos fuera de la partición actual. Los cuerpos contienen labels/gotos y llamadas nativas a otras funciones recompiladas; hay dispatch por direcciones guest para transfers indirectos. No hay intérprete ARM64/JIT como fallback del runtime. [S3], [S4], [S5]

La presencia de una función generada **no significa que todas sus instrucciones estén soportadas**: el generador puede emitir `rt_udf` para instrucciones no levantadas. Su combinación C/asm para SIMD es útil, pero deben distinguirse las rutas de host admitidas y las operaciones realmente implementadas. [S4], [S6], [S7]

Unicorn se usa offline para reconocer/evaluar prólogos de jump tables. No es el motor del juego en producción. El fallback de BR que enumera todos los labels de una función es mucho más permisivo que nuestra recuperación local validada: no hay que copiarlo como autorización de control flow. [S4]

El lector FDE devuelve `[]` ante determinados errores. Para nosotros debe producir rechazo tipado, con conteos/rangos verificados y registro explícito de zonas sin cobertura FDE. Nunca interpretar un fallo de parseo como «el módulo no tiene unwind». [S3]

### Cobertura ISA, flags y sysregs

El lifter cubre grandes familias de aritmética/lógica entera, shifts/bitfields, mul/div, cargas/stores, branches, flags NZCV, exclusivas y FP/SIMD. Es una ventaja frente a nuestra incorporación incremental, pero no «100% ARM64»: hay variantes rechazadas y `rt_udf` en cuerpos generados. El modo C x64 no equivale al asm ARM64 del host original. [S6], [S7]

Los sysregs se seleccionan explícitamente: TPIDR/TPIDRRO, NZCV, FPCR/FPSR y contadores tienen rutas; varios registros de identificación se sintetizan con constantes. La lectura de tiempo y mantenimiento de caché tampoco pueden copiarse como comportamiento universal del SDK. Nuestro HLE conserva selección de Rt, descarte XZR y diagnósticos: reutilizar decoders no debe perderlo.

Se inspeccionaron `test_lift.py`, `test_simd.py` y harnesses; no se ejecutaron sus suites CPU en esta auditoría. La prueba upstream realizada fue la de layout (55 checks), no una validación diferencial de todo su lifter ni de nuestra adaptación.

### ABI y control de flujo

SW usa `Cpu`, de 1024 bytes; los vectores empiezan en offset 512. Nuestro estado ABI es de 816 bytes. No basta con renombrar estructuras o hacer un cast. [S8]

`RET` se levanta como retorno sin conservar el registro Rn y se emite como retorno C; BL/BLR se apoyan en llamadas host. Nuestro contrato conserva direcciones guest, LR/SP, targets de retorno y fallos de dispatch. Una función C llamada directamente puede eludir esas verificaciones si se importa el emisor literalmente. Tampoco se deben importar sus rutas setjmp/longjmp o callbacks como sustituto del modelo de continuaciones/Program. [S6], [S9]

El valor reutilizable es principalmente la decodificación y las operaciones puras. Los accesos a memoria deben convertirse a nuestras APIs, con fallo antes de efectos parciales, y los transfers al modelo guest. Eso es un backend adaptado real, no un pequeño shim ABI. La conveniencia se debe medir antes de adoptar el lifter completo.

### Memoria, atomics y FP

- Memoria ordinaria: casts directos de guest VA a puntero host. Windows reserva una ventana y puede comprometer páginas ante accesos, con permisos de runtime menos estrictos que los nuestros. Incompatible con guest VA separado, permisos y negativos de RO/OOB. [S8], [S10]
- Exclusivas: guardan dirección y valor, y usan CAS. No rastrean el tamaño ni la invalidación de dominio que necesitamos. ABA y mezclas de tamaños son negativos obligatorios; no importar este monitor. [S8]
- FP/SIMD: hay control de FPCR/host FP y muchas operaciones, pero el backend C tiene limitaciones explícitas de FPSR/QC. Mantener nuestro tratamiento de NaN, rounding, FPCR/FPSR y probar cada helper reutilizado, incluidos modos admitidos y rechazo de otros. [S7], [S8]
- Errores: un fatal o un retorno cero no sustituye nuestros fallos tipados, sticky faults, diagnóstico y pruebas de ausencia de efectos.

**Conclusión D008:** SW demuestra viabilidad práctica de C AOT para BOTW, no el coste de C con nuestras comprobaciones ni la cobertura necesaria para TOTK. Es motivo suficiente para priorizar la medición de esta ruta, no para cerrar la decisión.

## 4. Loader, constructores, servicios y FS

### Loader y relocaciones

SW valida build IDs y carga tres segmentos, MOD0/dynamic, símbolos, RELA/JMPREL y RELR. Su soporte RELR es referencia útil para módulos/SDK posteriores; no es el bloqueo de nuestros módulos actuales. [S2], [S11]

Diferencias que impiden el reemplazo directo:

- Dynamic/symtab/relocs accedidos mediante punteros sin el mismo cierre de rangos que nuestro loader.
- Una definición propia gana antes del lookup HLE; la precedencia no replica nuestro contrato Mac.
- `*where = s ? s + addend : 0` pierde el addend de un weak indefinido cuando S=0. No reproduce nuestro caso weak+addend.
- Imports sin implementación pueden adquirir un stub que devuelve cero; en nuestro contrato deben quedar identificados y fallar tipadamente si no están implementados.
- RELR necesita su propio cierre de rangos/overflow si se adopta; tener el bucle no basta. [S11], [S14]

### DT_INIT_ARRAY: el problema actual es de iteración, no metadata ausente

SW no necesita `STT_FUNC` para todos los constructores porque ya considera otros metadatos, sobre todo FDE. Nuestros 10 700 targets están presentes en sus boundaries iniciales. La primera entrada sin STT_FUNC no es una anomalía que requiera inventar una root BLR general.

D023 ya resuelve conservadoramente la admisión del constructor alcanzado. El ensayo de 24 iteraciones no demuestra que ese mecanismo sea incapaz de avanzar: demuestra el coste del ciclo emitir/compilar/rearrancar repetido. La oportunidad es **desacoplar compilación de activación**:

1. Preparar candidatos de compilación desde la tabla completa validada y metadata contrastada.
2. Conservar fuera del conjunto activo lo que todavía no tenga autoridad bajo la política vigente.
3. Preservar el loop guest original, su cursor y el orden real de llamadas.
4. Hacer que un destino compilado pero no autorizado continúe produciendo exactamente el resultado actual, nunca un call host directo.

Esto necesita diseño y aprobación antes de modificar registro/activación de código. **No propongo registrar automáticamente todas las relocaciones como roots.** Tampoco se debe copiar el orden de inicialización de SW: llama inicialización SDK y después los demás módulos en orden inverso, mientras nuestra secuencia parte de la referencia Mac. La paridad completa del orden para TOTK sigue siendo una cuestión separada. Los valores x2/x3 usados como argumentos de init no son un número de repeticiones. [S12]

### Boot: callbacks, finalizadores y TLS

SW busca `Start` por símbolo con tres callbacks y fallback al de dos. x0 es el thread handle, x1 el args-region; x2 apunta a init-SDK, x3 a init-main y x4, cuando existe, a fini-main. x2 inicializa sólo SDK; x3 recorre los otros módulos en orden inverso de carga; x4 los finaliza en orden de carga, sin SDK. [S12]

Por módulo se llama al `DT_INIT` guest; sólo si falta, el host itera `DT_INIT_ARRAY`. Para fini se prefiere `DT_FINI`; sin él, `DT_FINI_ARRAY` se recorre al revés. Este fallback host no prueba nuestra ruta original de `__nnmusl_init_dso` ni puede saltarse su registro DSO/TLS. No se verificó ejecución de finalizadores en TOTK durante la auditoría.

Prioridad/tamaño de stack y program ID proceden de NPDM. El kernel crea TLR de 0x200 bytes por thread y usa TPIDRRO para IPC/TLS; `guest_call` restaura x30, sin nuestras comprobaciones de profundidad, SP/AAPCS y sticky faults. Preservar D016; el stack host de 256 MB de SW no sustituye un contrato de llamadas. El orden SDK temprano/main tardío merece contraste específico, no adopción por similitud entre títulos. [S9], [S13]

### SVC e IPC

SW tiene implementaciones de threads/eventos/handles, waits y memoria, y una capa HIPC/CMIF/TIPC con unas 21 familias de servicios. Es una buena referencia de comandos, descriptores, objetos y recursos que probablemente encontraremos después de los constructores. No equivale a soporte completo de Horizon. [S13], [S14]

Ejemplos que no se deben copiar: MapMemory mediante copia en lugar de alias; cambios de permiso que no aplican la protección guest requerida; valores de versión/GetInfo elegidos para BOTW; comandos desconocidos con respuesta de éxito; objetos vacíos que silencian servicios no implementados. Hay que adaptar protocolos a nuestras regiones/handles y conservar rechazo tipado. No sustituir nuestro control de thread/ABI por llamadas host libres.

Inventario por nombre: `sm:`, `audren:u`, `audout:u`, `acc:u0`, `appletOE`, `apm`, `lm`, `fsp-srv`, `hid`, `hid:sys`, `set`, `set:sys`, `pctl`, `pctl:s`, `pctl:a`, `pctl:r`, `aoc:u`, `nfp:user`, `time:u`, `time:a`, `time:s`. La cobertura no es homogénea: varias rutas de applet/control/DLC son objetos o valores ficticios. `runtime/hle/` añade bindings por símbolo para memoria/heaps, vi, tiempo, input, setjmp, etc. [S13], [S14]

Para nuestro boot, las comparaciones inmediatas son GetInfo/SetHeapSize, QueryMemory, identidad/prioridad del thread y map/unmap físico: ya tenemos contratos estrechos contrastados. No adoptar sus tamaños GetInfo, firmware fijo 8.1.0, copy-MapMemory ni escalado de heaps BOTW. La codec IPC es candidata a adaptación, pero sus counts/descriptores y buffers deben cerrarse contra longitud y capacidad antes de cualquier handler.

### FS/RomFS

SW construye/consume una RomFS de datos suministrados por el usuario y expone servicios de filesystem/storage. También enlaza rutas a directorios host para saves. Nuestro provider inmutable, rangos, manifest y aislamiento ya son una mejor base para el hito presente. [S15]

Pueden reutilizarse conocimiento de comandos y serialización; no la suposición de que una ruta guest es segura para el FS host. Deben probarse traversal/links, tamaños, errores, lifetime y permisos. Zero-fill con éxito al leer fuera del tamaño no se puede trasladar sin validar el contrato concreto de IStorage. Un `Commit` sin implementación transaccional tampoco prueba persistencia/atomicidad. Nada de esto obliga a reescribir el provider que ya funciona.

## 5. NVN y gráficos: oportunidad real, pero no backend listo para TOTK

### Resultado importante de compatibilidad

El binario original de TOTK compara **major == 55** y **minor >= 15** en su guard de NVN. SW anuncia/implementa la interfaz **55.15** para BOTW. Esto elimina la objeción de una incompatibilidad de versión evidente. El comentario 53.105 del header parcial local no es evidencia del contrato runtime de TOTK. [S16]

**No demuestra:** tamaño de cada objeto, todos sus offsets, entry points usados, semántica de sincronización, ni que la minor aceptada tenga todas las capacidades requeridas. Hay que obtener un corpus real de getters/SetDefaults/objetos/entradas antes de copiar estructuras.

El inventario SW contiene 515 wrappers sobre 569 nombres conocidos: 54 ausentes y 86 cuerpos vacíos, es decir, 429 cuerpos no vacíos. Son conteos de código, no cobertura semántica ni «75% de G5». Una función larga también puede ser una aproximación. [S16]

### Partes aprovechables

Existe trabajo sustancial en device/swapchain Vulkan, buffers, imágenes, formatos, samplers, descriptor state, render passes/pipelines, draws/dispatch, block-linear swizzle y shaders. Es un punto de partida mucho más concreto que una traducción mecánica de `nvn_mtl.m`. [S17], [S18]

La ruta de shaders es **Maxwell → GLSL → shaderc → SPIR-V**, no la misma que nuestro Maxwell→SPIR-V existente. Vertex/fragment/compute tienen implementación; geometry/tessellation y determinados modos/opcodes no están cubiertos. Debemos comparar rutas con corpus de shaders TOTK y rechazar etapas/operaciones no soportadas, no clasificarlas silenciosamente como otra etapa. [S19]

### Acoplamientos y riesgos que exigen adaptación

- Objetos NVN guardan punteros host en almacenamiento guest. En nuestro diseño deben sustituirse por registros host/IDs con lifetime validado, no filtrar punteros ni asumir identidad VA.
- GPU/CPU VA y memoria: existen supuestos de identidad y soporte limitado de memoria virtual/aliasing. El fallback de acceso de shaders a memoria host no es equivalente en todos los dispositivos.
- Coherencia: dirty tracking por muestreo/hash y recursos cacheados puede no observar una escritura guest; se necesitan controles que modifiquen bytes fuera de la muestra.
- Sincronización: barriers amplias, waits/eventos y fences aproximados o vacíos no sustituyen el contrato NVN. Probar señalización no satisfecha, visibilidad entre queues, readback y lifetime.
- Render targets, depth/stencil, formatos, swizzle, queries/timestamps y transiciones tienen caminos incompletos o específicos de la carga observada en BOTW.
- Un build Vulkan que presenta un triángulo no cierra G5 ni prueba que las copias/alias/CPU invalidate estén bien. [S17], [S18], [S19]

### Compatibility probing propuesto para TOTK

1. Version guard ya contrastado; obtener además la tabla real de `nvnDeviceGetInteger` del SDK TOTK, no copiar los 105 valores de BOTW ni nuestros valores heredados sin validar.
2. Inventariar nombres resueltos por bootstrap/GetProcAddress; cruzarlos con implementados/vacíos/ausentes, conservando fallo explícito.
3. Medir tamaños/alineación/offsets en SetDefaults/Initialize del SDK original. Canarios/guard pages alrededor de cada objeto; tamaños completos, no sólo `sizeof` de nuestra estructura menor.
4. Cubrir formatos, targets, swizzle 2D/3D, mipmaps y pools de descriptores con vectores independientes de BOTW.
5. Registrar mappings virtuales, aliases y LDG/STG. La ausencia de `VK_EXT_external_memory_host` no puede convertir lecturas en cero silenciosamente.
6. Corpus de shaders por etapa/opcode; compilar SPIR-V no basta: comparar resultados observables. Geometry/tessellation desconocidos son rechazo, no compute por defecto.
7. Negativos de WaitSync/eventos sin señal, visibilidad CPU/GPU, escritura fuera de bytes muestreados y destrucción con trabajo pendiente.
8. Sólo después decidir D007 y qué archivos Vulkan se adaptan. No importar el patch de frame-loop por LR ni timestamps ficticios para mantener resolución dinámica de BOTW.

**Cuánto se puede ahorrar:** bastante código de infraestructura y algoritmos bien delimitados podría evitarse; no sabemos aún cuánto de la integración y validación. No hay base para dar horas ni porcentajes. El conteo de wrappers o las estimaciones del README no son estimaciones del trabajo restante de TOTK.

**D007 propuesto:** priorizar un spike Vulkan sobre este material y comparar con la semántica Mac ya validada. Mantener abierta la selección hasta obtener evidencia de ABI, shader coverage y sincronización. Mientras G3 siga abierto, esto debe permanecer en investigación/pruebas acotadas, no convertirse en una reimplementación gráfica paralela.

## 6. Licencias y procedencia

El código propio de SW está bajo MIT, copyright 2026 Revivedx y los colaboradores, más Peiikai por LAS. El LICENSE declara expresamente fuera de esa cobertura propiedades Nintendo, datos/código del juego y componentes de terceros. LAS Recomp también tiene licencia MIT para su código propio, copyright 2026 Peiikai; conservar ambos notices cuando se reutilice material derivado de LAS. [S20], [L1]

| Material | Situación observada | Acción |
|---|---|---|
| Código propio SW/LAS | MIT | Reutilizable con notices; no incluye código generado del juego ni assets. |
| Unicorn | GPLv2; empleado offline por tooling | No enlazar ni distribuir como parte del runtime MIT. Mantener como herramienta de desarrollo separada, o sustituir ese reconocimiento si adoptamos el generador. No copiar su código al runtime. [L2] |
| FFmpeg | Base LGPL; ciertas configuraciones activan GPL/nonfree | El script dedicado busca build LGPL, pero eso no certifica cualquier DLL precompilada. Auditar flags y binarios; no empaquetar ciegamente la distribución MSYS2 GPL. [S21], [L3] |
| shaderc / astc-encoder | Apache-2.0 | Conservar LICENSE/NOTICE aplicables; fijar versiones y licencias transitivas. [L4], [L5] |
| VMA | MIT | Conservar notice de la versión fijada. [L6] |
| SDL3 | zlib | Conservar licencia; no es necesario adoptar su UI/runtime para usar otros componentes. [L7] |
| Dear ImGui / SMAA / FiraSans | MIT / MIT / OFL-1.1 en copias inspeccionadas | Mantener notices correspondientes; no confundir assets de terceros con MIT raíz. |
| Código descrito como port de Ryujinx | Procedencia indicada; notices no completamente resueltos en SW | Revisar upstream/derivación y conservar atribuciones antes de reutilizar audio. Nuestro árbol ya conserva un notice Ryujinx-Audio: no eliminarlo. |
| Envytools y documentación de hardware | Referencia externa, no dependencia runtime automática | El COPYING inspeccionado es MIT; comprobar licencia por archivo si se copia código, no inferirla del nombre del proyecto. [L8] |

El helper `swgen` merece tratamiento separado: el release lo congela con Unicorn dentro de su proceso y el runtime lo lanza como herramienta externa. Que no esté enlazado en `savagewind.exe` no elimina las obligaciones GPL del helper distribuido. No recomiendo copiar ese paquete sin inventario/textos/source offer revisados; sustituir el reconocimiento offline evita esa dependencia si se decide así. GCC runtime/PyInstaller también tienen excepciones específicas, no licencias MIT por pertenecer al zip.

No se detectó una razón para rechazar la reutilización del código propio MIT de SW. Tampoco se ha realizado una auditoría legal de cada línea o artefacto binario: antes de distribuir, inventario/SBOM, hashes, textos de licencia y revisión de dependencias exactas. El copyright Nintendo y datos de juego quedan siempre fuera.

## 7. Modelo de build y decisiones propuestas

SW genera game code localmente desde los ficheros del usuario, sin distribuirlo con el runtime. Una `swgame.dll` contiene tablas por NSO (nombre/base/tamaño/build ID y arrays ordenados de direcciones/funciones); exporta `swgame_tables`. Se validan ABI e identidad del generador/headers. La exe carga la DLL y aporta imports al código generado; Linux usa `.so`. El split es una DLL de juego con tablas por módulo, no necesariamente una DLL por NSO. [S5], [S22]

El build usa clang o `zig cc`, chunks paralelos y flags C específicos, normalmente `-O1 -fno-strict-aliasing`. `__uint128_t`, GNU attributes, builtins y musttail no son un reemplazo directo de nuestra compilación MSVC. No hace falta reemplazar el toolchain entero para reutilizar metadata/operaciones.

La documentación upstream registra una corrida de 195 675 funciones, 551,8 MB de C, 608 unidades, 62 s de generación y 19 min 1 s de compilación/link a 12 jobs, DLL 198,8 MB; otra revisión registra 16 min 9 s y 211,7 MB. **Son mediciones publicadas para BOTW, no reproducidas aquí ni predicciones de TOTK.** Identifican switches de miles de labels como gran coste de compilación: otro motivo para no importar el fallback all-labels. El README actual sitúa la primera setup build alrededor de 40 min: tampoco debe prometerse el mejor número histórico. [S23], [S1]

Conservar la separación de copyright y generar/build fuera del árbol es compatible con nuestra higiene. Adoptar el split exige un ABI/DLL ID explícito, hashes de inputs y tabla activa validada; no exportar cualquier función nativa como dirección guest ni aceptar sólo un filename para identificar la biblioteca.

| Decisión | Recomendación propuesta, sin editar DECISIONS |
|---|---|
| D008 | Priorizar frontend/chunks/backend C adaptado. No cerrar C vs otra estrategia hasta medir con nuestras garantías. |
| D010 | Mantener layout 816 B y salidas finitas. SW no aporta evidencia para cambiarlo. |
| D015 | Mantener Program inmutable, todos los PC resueltos como guest VA y thunks estables. Cache de cuerpos no es autorización ni tabla activa automática. |
| D016 | Mantener nested calls limitadas, SP/AAPCS verificados y sticky fault; no sustituirlos por C recursion/longjmp. |
| D023 / código-datos | Mantener autoridad conservadora y guards originales. Separación compilado/activo necesita aprobación y negativo propio; FDE añade evidencia, no roots generales. |
| D007 | Priorizar spike Vulkan/NVN, selección abierta hasta los probes. |

## 8. Experimento mínimo y cambios propuestos al roadmap

**No se implementa durante esta auditoría.** Requiere aprobación de alcance, no autorización tácita para cambiar roots.

### Etapa A — contrato frontend, sin cambiar ejecución

- Adaptar NSO/FDE/partición a un manifest de candidatos con hash del módulo y procedencia de cada boundary.
- Parseo fail-closed, zonas sin FDE explícitas, known-DATA preservado.
- No incorporar BL/ADR/RELATIVE indiscriminados como entry points.
- Comparar el constructor main `0x1520` y el switch local SDK que ya validamos. El fallback de BR no resuelto sigue siendo tipado.

### Etapa B — equivalencia y separación de autoridad

- Emitir esos casos mediante el frontend adaptado **hacia nuestro ABI/Program/memoria**, no invocar el runtime SW.
- Comparar traza de GPR/SP/NZCV/FPCR/FPSR, transfers y escrituras con nuestro traductor actual; Unicorn sólo como tercer oráculo offline cuando corresponda.
- Negativos obligatorios: boundary erróneo, RO/OOB, SP desalineado, retorno alterado, exclusivas ABA/tamaño y compilado-pero-no-autorizado.
- La última prueba debe seguir rechazando la llamada aunque el cuerpo ya exista en código nativo. La autoridad es la clausura CFG de las roots admitidas por la política vigente, no el conjunto de funciones compiladas.

### Etapa C — rendimiento de iteración, no FPS

Sólo si B conserva los contratos:

- Seleccionar un lote de unos 32 constructores/callees, **estratificado** por llamadas, tablas, FP/SIMD, exclusivas y ausencia de FDE; no sólo los primeros fáciles.
- Mantener el loop guest y sus guards. Estudiar almacenamiento de cuerpos precompilados y selección del conjunto activo, sin generar código ejecutable en runtime ni permitir llamadas directas que eludan Program.
- Medir tiempo de parseo/emisión/compilación/link, tamaño, instrucciones no soportadas y número de rebuilds evitados por constructor nuevo.
- Mantener la salida G2 congelada y todos los tests negativos del runtime.
- Si adaptar el lifter exige reemplazar casi todas sus rutas de memoria/control, documentar ese coste: puede convenir adoptar sólo discovery/build y conservar más de nuestro emisor.

**Criterio de decisión:** adoptar la generación anticipada si reduce de forma medida el ciclo por constructor sin perder ninguna garantía. Si no lo hace, retener el frontend/manifest útil y descartar el resto. Sólo entonces proponer D008 concreto; D007 sigue su propio spike posterior.

### Impacto propuesto

- **G3:** priorizar este experimento de frontend/build antes de añadir más heurísticas de roots. Separar el cierre de constructores de la cobertura ISA restante. No declarar G3 completo por los conteos de metadata.
- **G4:** reusar conocimiento IPC/servicios sobre nuestro provider y memoria; implementar únicamente comandos realmente alcanzados, con errores explícitos para los demás.
- **G5:** usar SW como base candidata del spike Vulkan/Maxwell, empezando por contrato NVN 55.15, tamaños/canarios, corpus de entry points, swizzle, shaders y negativos de sync/alias. No copiar `nvn_mtl.m` ni abrir implementación gráfica amplia mientras el gate anterior siga bloqueado.

No se cambia ningún exit condition ni decisión permanente en este informe. Ésta es la propuesta para decidir qué experimento autorizar a continuación.

## 9. Respuestas directas a las siete preguntas

1. **¿Continuar nuestro recompiler o pivotar?** Pivote parcial de frontend/discovery/build; no reemplazo wholesale de lifter/runtime. Adoptar operaciones del lifter sólo por equivalencia. Conservar ABI/Program, memoria, permisos, fallos, exclusivas y FP.
2. **¿Cómo cambia D008?** De opciones abstractas a un experimento prioritario y concreto de generación C adaptada. Sigue OPEN hasta medir compatibilidad, cobertura y coste bajo nuestras garantías.
3. **¿DT_INIT_ARRAY?** SW encuentra los targets y lo confirmamos en TOTK. D023 ya admite el constructor alcanzado: mejorar el ciclo con precompilación separada de autoridad, manteniendo el loop original. Nunca cualquier BLR como root.
4. **¿G4 reutilizable?** Codecs/mapas de comandos/handlers seleccionados, con guest-memory adapters y errores explícitos. Poco ahorro adicional para el provider ya implementado; sí menos reverse engineering de IPC/servicios. Sin porcentaje defendible.
5. **¿G5 reutilizable?** Infraestructura Vulkan, formatos/swizzle y traductor Maxwell son activos considerables. No sabemos cuánto de integración/coherencia/etapas/layout NVN requiere TOTK. Probe primero, sin porcentaje ni calendario inventado.
6. **¿Experimento mínimo?** Constructor `0x1520` + switch SDK con frontend adaptado y nuestro runtime, comparación y negativos; después lote estratificado, midiendo rebuilds evitados.
7. **¿Cambiar roadmap G3–G5?** Sí como propuesta: spike frontend/build antes de más políticas de roots; G4 conserva provider y aprovecha protocolos; G5 prioriza probe Vulkan/NVN. D007/D008 no se cierran ni se saltan gates. Ninguna modificación automática de DECISIONS.

## Referencias primarias

[S1]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/README.md
[S2]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/tools/nso.py
[S3]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/tools/analyze.py#L60-L108
[S4]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/tools/gen.py
[S5]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/gamebuild.c
[S6]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/tools/lifter.py
[S7]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/tools/simd_c.py
[S8]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/cpu.h#L7-L98
[S9]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/dispatch.c
[S10]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/platform/windows.c
[S11]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/loader.c#L68-L267
[S12]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/main.c
[S13]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/kernel.c
[S14]: https://github.com/ikeracevedo2002/SavageWindRecomp/tree/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/services
[S15]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/services/fs.c
[S16]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/nvn/objects.c
[S17]: https://github.com/ikeracevedo2002/SavageWindRecomp/tree/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/nvn/vulkan
[S18]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/nvn/nvn.h
[S19]: https://github.com/ikeracevedo2002/SavageWindRecomp/tree/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/nvn/maxwell
[S20]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/LICENSE
[S21]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/tools/build_deps_windows.sh
[S22]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/runtime/gamelib.h
[S23]: https://github.com/ikeracevedo2002/SavageWindRecomp/blob/575ad88e02f9a89a9a885d90039d48af33c982f4/docs/SAVAGE-WIND.md#L839-L897
[L1]: https://github.com/peiikai/LASRecomp/blob/main/LICENSE
[L2]: https://github.com/unicorn-engine/unicorn/blob/master/COPYING
[L3]: https://www.ffmpeg.org/legal.html
[L4]: https://github.com/google/shaderc/blob/main/LICENSE
[L5]: https://github.com/ARM-software/astc-encoder/blob/main/LICENSE.txt
[L6]: https://github.com/GPUOpen-LibrariesAndSDKs/VulkanMemoryAllocator/blob/v3.3.0/LICENSE.txt
[L7]: https://github.com/libsdl-org/SDL/blob/main/LICENSE.txt
[L8]: https://github.com/envytools/envytools/blob/master/COPYING
