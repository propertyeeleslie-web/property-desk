// ----------------------
// api/login.js (CommonJS, Vercel)
// ----------------------
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jose = require("jose").default;

// Supabase 连接
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const JWT_SECRET = process.env.JWT_SECRET || "propertydesk123";

// 设置 CORS
function corsHeaders(res){
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
}

// 主处理函数
module.exports = async function handler(req, res){
  corsHeaders(res);

  // 处理预检请求
  if(req.method === "OPTIONS") return res.status(200).end();

  if(req.method !== "POST") return res.status(405).json({error:"Method not allowed"});

  try {
    const { email, password } = req.body;
    if(!email || !password) return res.status(400).json({error:"Email and password required"});

    // 查询用户
    const { data: users, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .limit(1);

    if(error) throw error;

    const user = users?.[0];
    if(!user) return res.status(400).json({error:"User not found"});

    // 校验密码
    const valid = await bcrypt.compare(password, user.password);
    if(!valid) return res.status(400).json({error:"Invalid password"});

    // 生成 JWT
    const token = await new jose.SignJWT({ id:user.id, role:user.role })
      .setProtectedHeader({ alg:"HS256" })
      .setExpirationTime("7d")
      .sign(new TextEncoder().encode(JWT_SECRET));

    return res.json({ token, role: user.role });

  } catch(e){
    console.error("Login error:", e);
    return res.status(500).json({error:"Internal server error"});
  }
};
