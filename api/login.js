export default async function handler(req,res){
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,PUT,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type,Authorization");

  if(req.method==="OPTIONS") return res.status(200).end();

import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";
import * as jose from "jose";

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
const JWT_SECRET = process.env.JWT_SECRET || "propertydesk123";

export default async function handler(req,res){
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Methods","POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type, Authorization");
  if(req.method==="OPTIONS") return res.status(200).end();

  if(req.method!=="POST") return res.status(405).json({error:"Method not allowed"});

  const { email, password } = req.body;
  const { data: users } = await supabase.from("users").select("*").eq("email", email).limit(1);
  const user = users?.[0];
  if(!user) return res.json({error:"User not found"});

  const valid = await bcrypt.compare(password, user.password);
  if(!valid) return res.json({error:"Invalid password"});

  const token = await new jose.SignJWT({id:user.id, role:user.role})
    .setProtectedHeader({alg:"HS256"})
    .setExpirationTime("7d")
    .sign(new TextEncoder().encode(JWT_SECRET));

  res.json({token, role:user.role});
  } catch(e){
    console.error("Login error:", e);
    res.status(500).json({error:"Internal server error"});
  }
}

