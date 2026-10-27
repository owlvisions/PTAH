# بتاح (PTAH) — دليل البدء

**بتاح** هو المنتج الأساسي في هذا المستودع: مجموعة أدوات لفهم البرامج والهندسة العكسية تقوم على **الدليل أولًا**. كل ادعاء يستند إلى دليل مسجَّل بمستوى ثقة محدد، ولا يُنفَّذ الملف المستهدف أبدًا. محرك REA الموروث يعمل تحت بتاح كطبقة توافق تُستدعى محللاتها عبر محوّلات محدودة.

> **الحالة:** المستودع معاينة ترحيل. اسم حزمة npm هو `@owlvisions/ptah` ولم تُنشَر على npm بعد؛ استخدم أوامر نسخة المصدر أدناه. الأمران القديمان `rea` و`rea-agents` يظلان متاحين كأسماء توافق.

## الضمانات

| الضمان              | ما يعنيه عمليًا                                                                                                                                                    |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| الدليل أولًا          | كل ادعاء يستشهد بأدلة مسجلة بثقة `observed` أو `derived` أو `inferred`. لا يظهر `verified` إلا إذا سجّلته خطوة تحقق فعلية.                                           |
| مرتبط ببايتات الهدف | التحقيق وكل دليل يحملان SHA‑256 الهدف؛ يُرفض الدليل القديم أو العابر للأهداف، ويكتشف `verify --target` أي انحراف.                                                    |
| لا تنفيذ للهدف       | البصمة والفحص واستخراج السلاسل وتشغيل المحللات تتم بوسائط ثابتة، بلا shell، بمهلة وحد للمخرجات؛ الهدف نفسه لا يُشغَّل.                                                   |
| حزم حالة محمولة     | `export-case` يلفّ التحقيق في غلاف `ptah-investigation-case` مع SHA‑256؛ `import-case` يرفض التلف وعدم تطابق الهدف. التوقيع Ed25519 والتشفير AES‑256‑GCM اختياريان. |
| سجل مقاوم للتلاعب    | كل تعديل يضيف إدخال تاريخ مُسلسل بالتجزئة؛ تعديل أو حذف أو إعادة ترتيب أي إدخال يُفشل التحقق.                                                                       |
| حتمية               | التقارير والرسوم والخطط والفروق ومخرجات lint وstats ثابتة بايتًا لنفس المدخلات.                                                                                     |
| محلي افتراضيًا       | الواجهة تعمل على loopback فقط، تتحقق من ترويسة Host، وتحذف مساحة العمل المؤقتة عند الإغلاق.                                                                         |

## المتطلبات

Node.js مدعوم: `^22.23.4 || ^24.22.1 || >=26.12.1`. أوامر بتاح الأصلية لا تحتاج تثبيت اعتماديات المشروع؛ محرك REA الموروث يحتاجها.

## سير عمل كامل

```sh
node scripts/ptah.mjs help
node scripts/ptah.mjs self-check --json
node scripts/ptah.mjs fingerprint --target ./sample.bin --inspect
node scripts/ptah.mjs strings --target ./sample.bin --min-length 8
node scripts/ptah.mjs carve --target ./sample.bin
node scripts/ptah.mjs init --target ./sample.bin --output ./sample.investigation.json
node scripts/ptah.mjs add-evidence --input ./sample.investigation.json --output ./sample.investigation.json \
  --id ev-1 --kind static-analysis --summary "رأس ELF64 لمعمارية AArch64" --source "ptah fingerprint --inspect" \
  --confidence observed --tags headers
node scripts/ptah.mjs add-claim --input ./sample.investigation.json --output ./sample.investigation.json \
  --id c-1 --text "الملف مكتبة مشتركة 64‑بت" --evidence-ids ev-1
node scripts/ptah.mjs set-claim-status --input ./sample.investigation.json --output ./sample.investigation.json \
  --id c-1 --status verified --reason "تمت ملاحظة الرأس مباشرة"
node scripts/ptah.mjs lint --input ./sample.investigation.json
node scripts/ptah.mjs stats --input ./sample.investigation.json
node scripts/ptah.mjs history --input ./sample.investigation.json
node scripts/ptah.mjs report --input ./sample.investigation.json --format markdown
node scripts/ptah.mjs graph --input ./sample.investigation.json --format mermaid
node scripts/ptah.mjs plan --input ./sample.investigation.json --steps 3
node scripts/ptah.mjs export-case --input ./sample.investigation.json --output ./sample.ptah-case.json.gz --gzip
node scripts/ptah.mjs keygen --output-dir ./keys
node scripts/ptah.mjs sign-case --input ./sample.ptah-case.json.gz --key ./keys/ptah-case-signing.key --output ./sample.signed.json
node scripts/ptah.mjs verify-case --input ./sample.signed.json --public-key ./keys/ptah-case-signing.pub --target ./sample.bin
node scripts/ptah.mjs diff --base ./yesterday.ptah-case.json --head ./sample.signed.json
node scripts/ptah.mjs eval --suite examples/ptah-eval
node scripts/ptah.mjs ui
```

## الأوامر

| الأمر                                                                                                                                        | الغرض                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `info`, `self-check`, `providers [--probe]`, `isolation`                                                                                    | معلومات المنتج، جاهزية البيئة، اكتشاف الأدوات، توفر bubblewrap/prlimit                                                                                |
| `fingerprint [--inspect]`, `strings`, `carve`, `asar`, `wasm`                                                                               | بصمة وتفاصيل الصيغة والإنتروبيا، سلاسل، توقيعات مضمّنة، أرشيف ASAR، أقسام WebAssembly — دون تنفيذ                                                       |
| `init`, `add-evidence [--artifact] [--tags]`, `add-claim`, `add-question`, `add-action`                                                     | بناء التحقيق                                                                                                                                         |
| `set-claim-status`, `resolve-question`, `freeze`, `unfreeze`                                                                                | تغيير الحالة بحراسة (`verified` يتطلب دليلًا ملاحَظًا)، حل الأسئلة، تجميد المحتوى                                                                          |
| `verify`, `lint`, `stats`, `history`, `schema`, `migrate`                                                                                   | التحقق من الانحراف، الجودة، المقاييس، سلسلة التاريخ، المخطط، الترحيل                                                                                  |
| `export-case [--gzip]`, `verify-case`, `import-case`, `sign-case`, `keygen`, `encrypt-case`, `decrypt-case`, `link-case`, `merge`           | الحزم المحمولة والتوقيع والتشفير والربط والدمج                                                                                                       |
| `report [--format markdown]`, `diff`, `graph [--format dot\|mermaid]`, `plan [--steps N]`                                                   | المخرجات القابلة للمراجعة                                                                                                                            |
| `analyze --provider ID [--isolation auto\|required\|none] [--cpu-seconds N] [--memory-mb N]`                                                | محللات مسموح بها: objdump, llvm-objdump, readelf, nm, file, rabin2, rz-bin, monodis, aapt2, wasm-objdump, wasm-tools                                  |
| `engine TASK\|matrix\|benchmark\|providers`, `agents list\|install\|uninstall\|print`, `upstream-sync`, `eval`, `watch`, `completion`, `ui` | محرك بتاح المستقل (33 مزوّدًا، 26 صيغة)، تسجيل بتاح لدى وكلاء البرمجة، الدمج التلقائي لتحديثات المصدر، التقييم، المراقبة، إكمال الصدفة، الواجهة المحلية |

يدعم كل أمر `--quiet` لكتم المخرجات؛ الأخطاء تظل على stderr. عبارة المرور للتشفير تُمرَّر عبر متغير البيئة `PTAH_CASE_PASSPHRASE` فقط.

## تحليل خارق بأمر واحد

| الأمر                                       | الغرض                                                                                                      |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| `triage --target F --output INV`           | يشغّل كل تحليل مناسب للملف ويسجّل الأدلة (مُلاحَظة) والقدرات (مُستنتَجة كفرضيات) والأسئلة المفتوحة والخطوات التالية |
| `structure`                                | تحليل ELF/PE أصلي: الأقسام مع الإنتروبيا، الاستيرادات، التصديرات، المكتبات، imphash، مؤشرات التغليف           |
| `hashes`, `search`, `hexdump`, `compare`   | بصمات متعددة، بحث بنمط ست عشري مع `??`، عرض بايتات محدود، مقارنة ملفين بدرجة تشابه                         |
| `iocs`, `secrets`, `capabilities`, `rules` | مؤشرات الاختراق، أسرار مُخفاة القيمة، قدرات سلوكية مع معرّفات ATT&CK، قواعد نصية/ست عشرية                     |
| `summary`, `query`, `timeline`, `doctor`   | ملخص موفّر للرموز، بحث في الأدلة، خط زمني، فحص جاهزية شامل                                                   |

أي أمر تحليل يقبل `--record INV` ليضيف نتيجته دليلًا إلى التحقيق تلقائيًا، و`report --format sarif|html` يصدّر التقرير لأدوات الفحص أو كصفحة مستقلة.

## الاستخدام مع وكلاء الذكاء الاصطناعي

يسجّل `ptah agents` خادم MCP الخاص ببتاح ويثبّت مهارة بتاح لدى Claude Code وClaude Desktop وOpenAI Codex وGemini CLI وGitHub Copilot (في VS Code وCLI) وCursor وWindsurf وOpenCode وQwen Code:

```sh
node scripts/ptah.mjs agents list                 # الحالة لكل وكيل
node scripts/ptah.mjs agents install              # معاينة للوكلاء المكتشفين دون كتابة
node scripts/ptah.mjs agents install --yes        # التطبيق مع نسخة احتياطية لكل ملف
node scripts/ptah.mjs agents install --client codex,cursor --yes
node scripts/ptah.mjs agents uninstall --all --yes
node scripts/ptah.mjs agents print --client codex # مقطع إعداد يدوي لأي وكيل آخر
node scripts/ptah.mjs agents install --workspace . --yes # إعداد المشروع مقيّدًا بمجلده
```

يدعم 15 وكيلًا: Claude Code وClaude Desktop وCodex وGemini CLI وCopilot (VS Code وCLI) وCursor وWindsurf وOpenCode وQwen Code وCline وRoo Code وKiro وAmazon Q وZed. ويتوفر بتاح أيضًا كإضافة Gemini (`gemini extensions install https://github.com/owlvisions/PTAH`) وكإضافة Claude Code (`/plugin marketplace add owlvisions/PTAH`).

لا يُعدَّل إلا مدخل `ptah`؛ لا يُستبدل خادم آخر بنفس الاسم إلا مع `--force`، ولا تُعاد كتابة ملفات JSON التي تحتوي تعليقات. التفاصيل في `docs/PTAH-AGENTS.md`.

## حدود صادقة

- checksum الحزمة يكشف التلف ولا يصادق على المؤلف؛ التوقيع Ed25519 يصادق على حامل المفتاح فقط.
- العزل عبر bubblewrap يُطبَّق عندما يكون متاحًا على Linux؛ وإلا يُبلَّغ عن غيابه صراحة ولا يُدّعى وجوده. استخدم `--isolation required` لفرضه.
- المحوّلات تستخرج بيانات وصفية؛ ليست تفكيكًا كاملًا ولا تحليلًا دلاليًا.
- ثوابت مجموعة التقييم اصطناعية (رؤوس مبنية يدويًا)؛ تُثبت الحزمة ولا تمثل برامج حقيقية.

## التحقق

```sh
npm run test:ptah
```

للتوثيق الكامل بالإنجليزية: `docs/PTAH-GETTING-STARTED.md` و`docs/PTAH-ENGINE-V1.md` و`docs/PTAH-MCP.md` و`docs/PTAH-UI.md`.
