import jwt from 'jsonwebtoken';
import { query } from './db.js';
const secret=()=>process.env.JWT_SECRET;
export const issueToken=(admin)=>jwt.sign({id:admin.id,role:admin.role},secret(),{expiresIn:'8h'});
export const requireAdmin=async(req,res,next)=>{try{const token=req.cookies?.terqivo_admin||req.headers.authorization?.replace('Bearer ','');if(!token)return res.status(401).json({message:'Authentication required'});const decoded=jwt.verify(token,secret());const rows=await query('SELECT id,name,email,role,is_active FROM admin_users WHERE id=? LIMIT 1',[decoded.id]);if(!rows[0]||!rows[0].is_active)return res.status(401).json({message:'Admin account inactive'});req.admin=rows[0];next()}catch(e){return res.status(401).json({message:'Invalid authentication token'})}};
