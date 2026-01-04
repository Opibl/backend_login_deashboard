import express from 'express'
import cors from 'cors'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import { createClient } from '@supabase/supabase-js'

dotenv.config()

/* ======================================================
   APP
====================================================== */

const app = express()
app.use(cors())
app.use(express.json())

/* ======================================================
   SUPABASE
====================================================== */

const supabaseUrl = 'https://upcayfwtsxpkwooljjtv.supabase.co'
const supabaseKey = process.env.SUPABASE_KEY // 🔑 service_role key
const supabase = createClient(supabaseUrl, supabaseKey)

/* ======================================================
   JWT
====================================================== */

const JWT_SECRET = process.env.JWT_SECRET

/* ======================================================
   MIDDLEWARES
====================================================== */

// 🔐 Auth middleware
const auth = (req, res, next) => {
  const header = req.headers.authorization
  const token = header?.split(' ')[1]

  if (!token) {
    return res.status(401).json({ message: 'No token provided' })
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET)
    req.user = decoded
    next()
  } catch {
    return res.status(401).json({ message: 'Invalid token' })
  }
}

// 👑 Admin middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' })
  }
  next()
}

/* ======================================================
   HEALTH CHECK
====================================================== */

app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

/* ======================================================
   AUTH
====================================================== */

// 🔑 LOGIN
app.post('/login', async (req, res) => {
  const { email, password } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password required' })
  }

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single()

  if (error || !user) {
    return res.status(401).json({ message: 'Invalid credentials' })
  }

  const validPassword = await bcrypt.compare(password, user.password)
  if (!validPassword) {
    return res.status(401).json({ message: 'Invalid credentials' })
  }

  const token = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      role: user.role,
    },
    JWT_SECRET,
    { expiresIn: '1h' }
  )

  res.json({
    token,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
    },
  })
})

// 👤 WHO AM I
app.get('/me', auth, (req, res) => {
  res.json({ user: req.user })
})


/* ======================================================
   ADMIN ROUTES
====================================================== */

// ➕ CREATE USER
app.post('/admin/create-user', auth, isAdmin, async (req, res) => {
  const { email, password, role } = req.body

  if (!email || !password) {
    return res.status(400).json({ message: 'Missing data' })
  }

  const hashedPassword = await bcrypt.hash(password, 10)

  const { data, error } = await supabase
    .from('users')
    .insert({
      email,
      password: hashedPassword,
      role: role || 'user',
    })
    .select()
    .single()

  if (error) {
    return res.status(400).json({ message: error.message })
  }

  res.status(201).json({
    message: 'User created',
    user: {
      id: data.id,
      email: data.email,
      role: data.role,
    },
  })
})

// 📋 LIST USERS
app.get('/admin/users', auth, isAdmin, async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, email, role, created_at')
    .order('created_at', { ascending: false })

  if (error) {
    return res.status(400).json({ message: error.message })
  }

  res.json(data)
})

// ❌ DELETE USER (protect last admin)
app.delete('/admin/users/:id', auth, isAdmin, async (req, res) => {
  const { id } = req.params

  const { data: admins } = await supabase
    .from('users')
    .select('id')
    .eq('role', 'admin')

  if (admins.length <= 1) {
    return res.status(403).json({ message: 'Cannot delete last admin' })
  }

  const { error } = await supabase
    .from('users')
    .delete()
    .eq('id', id)

  if (error) {
    return res.status(400).json({ message: error.message })
  }

  res.json({ message: 'User deleted' })
})

/* ======================================================
   PROTECTED TEST ROUTE
====================================================== */

app.get('/dashboard', auth, (req, res) => {
  res.json({
    message: 'Welcome to dashboard',
    user: req.user,
  })
})

/* ======================================================
   SERVER
====================================================== */

const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`)
})
