const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '', 
    database: 'football_academy'
});

const JWT_SECRET = 'my_super_secret_key_123';

db.connect((err) => {
    if (err) {
        console.error('فشل الاتصال بقاعدة البيانات:', err);
    } else {
        console.log('تم الاتصال بقاعدة البيانات بنجاح.');

        const localHash = bcrypt.hashSync('password', 10);

        // تنظيف الجدول وإعادة إدخال (المدير + المدرب) محلياً لضمان الأمان
        db.query('TRUNCATE TABLE users', (err) => {
            if (err) return console.error(err);

            const sql = 'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)';
            
            // 1. حساب المدير
            db.query(sql, ['المدير العام', 'admin@academy.com', localHash, 'admin']);
            // 2. حساب المدرب التجريبي الجديد
            db.query(sql, ['الكابتن أحمد (مدرب الفئات السنية)', 'coach@academy.com', localHash, 'coach'], (err) => {
                if (!err) console.log('✅ تم تهيئة حسابات المدير والمدرب بالهاش المحلي المضمون!');
            });
        });
    }
});

// === دالة الأمان والحماية (Middleware) ===
// هذه الدالة تمنع أي شخص من تصفح بيانات السيرفر إلا إذا كان يملك توكن حقيقي وصالح
function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    
    if (typeof bearerHeader !== 'undefined') {
        const bearerToken = bearerHeader.split(' ')[1]; // استخراج التوكن الصافي
        
        jwt.verify(bearerToken, JWT_SECRET, (err, authData) => {
            if (err) {
                return res.status(403).json({ message: 'التوكن غير صالح أو منتهي الصلاحية' });
            } else {
                req.user = authData; // حفظ بيانات المستخدم المشفرة داخل الطلب لنعرف دوره
                next(); // السماح له بالانتقال للرابط المطلوب
            }
        });
    } else {
        res.status(401).json({ message: 'غير مسموح بالدخول: لم يتم إرسال توكن الحماية' });
    }
}

// رابط تسجيل الدخول الأساسي
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) return res.status(500).json({ message: 'خطأ في السيرفر' });
        if (results.length === 0) return res.status(401).json({ message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });

        // نضع الـ role داخل التوكن بشكل مشفر ومحمي
        const token = jwt.sign({ id: user.id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });

        res.json({ message: 'تم تسجيل الدخول بنجاح', token });
    });
});

// === رابط محمي بالكامل يوزع الصلاحيات بناءً على الدور (Protected Route) ===
app.get('/api/dashboard/data', verifyToken, (req, res) => {
    // بفضل دالة verifyToken، السيرفر هنا يعرف بدقة من أنت وما هو دورك (req.user)
    if (req.user.role === 'admin') {
        res.json({
            name: req.user.name,
            role: req.user.role,
            secretData: "🔒 بيانات سرية للمدير: إجمالي أرباح الأكاديمية هذا الشهر هو 5000$ ويمكنك تعديل صلاحيات الموظفين."
        });
    } else if (req.user.role === 'coach') {
        res.json({
            name: req.user.name,
            role: req.user.role,
            secretData: "📋 بيانات خاصة بالمدرب: جدول تدريبات اليوم يحتوي على حصتين تدريجيتين، وليس لديك صلاحية لرؤية الحسابات المالية."
        });
    } else {
        res.status(403).json({ message: 'غير مصرح لك برؤية هذه البيانات' });
    }
});

// === رابط تسجيل لاعب جديد (خاضع للحماية) ===
app.post('/api/players', verifyToken, (req, res) => {
    const p = req.body;

    // حساب تاريخ الانتهاء تلقائياً في السيرفر بزيادة شهر واحد عن تاريخ البدء (كأمان إضافي)
    const startDate = new Date(p.start_date);
    startDate.setMonth(startDate.getMonth() + 1);
    const autoEndDate = startDate.toISOString().split('T')[0];

    const sql = `INSERT INTO players 
    (name, birth_date, position, phone, member_number, address, gender, preferred_foot, 
    program_type, branch, start_date, end_date, session_time, session_count, 
    allergies, chronic_diseases, past_injuries, current_medications, height, weight, 
    fee, payment_date, payment_method, discount) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    const values = [
        p.name, p.birth_date, p.position, p.phone, p.member_number || null, p.address || null, p.gender, p.preferred_foot,
        p.program_type, p.branch, p.start_date, autoEndDate, p.session_time, p.session_count,
        p.allergies || null, p.chronic_diseases || null, p.past_injuries || null, p.current_medications || null, p.height || null, p.weight || null,
        p.fee, p.payment_date, p.payment_method, p.discount || 0.00
    ];

    db.query(sql, values, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'حدث خطأ أثناء حفظ بيانات اللاعب في قاعدة البيانات' });
        }
        res.json({ message: '✅ تم تسجيل اللاعب بنجاح وحساب فترة الاشتراك تلقائياً!' });
    });
});

app.listen(5000, () => console.log('السيرفر يعمل على بورت 5000'));