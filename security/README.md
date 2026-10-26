وحدة الأمان وحماية الحاويات (Security Module)
1. الثغرات المكتشفة في النسخة التجريبية (Vulnerabilities):
Hardcoded Secret: وجود مفاتيح وصول سرية AWS_SECRET_KEY مباشرة داخل إعدادات الحاوية.
Root Execution: تشغيل الحاوية بصلاحيات الجذر الافتراضية.
Exposed Ports & Services: تثبيت خادم SSH غير ضروري وفتح المنفذ 22 خارجياً مما يرفع مساحة الهجوم.
2. قواعد الإصلاح الأمني للنظام (Security Guardrails):
Principle of Least Privilege: تم إنشاء مستخدم غير جذري (appuser) مع ضبط صلاحيات المجلد chown لمنع تشغيل التطبيق كـ Root.
Attack Surface Reduction: إزالة تثبيت خادم SSH وإلغاء فتح المنفذ 22 والإبقاء فقط على المنفذ التشغيلي الأساسي 5000.
Secret Hygiene: حذف كتابة المفاتيح السرية في ملف البناء لضمان تمريرها عبر بيئة التشغيل الآمنة (Runtime Environment Variables).
Business Continuity: الحفاظ على مسار العمل WORKDIR وأمر التشغيل CMD لضمان استمرارية الخدمة دون أخطاء برمجية.
