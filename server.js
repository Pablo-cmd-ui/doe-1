import express from 'express'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'

const prisma = new PrismaClient()
const app = express()

// Necessário para resolver caminho do arquivo HTML
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

app.use(cors())
app.use(express.json())

// JWT Secret Key (mova para um arquivo .env depois)
const JWT_SECRET = 'sua_chave_secreta_aqui'

// Servir o formulário de cadastro
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'cadastro.html'))
})

// Criar usuário
app.post('/usuarios', async (req, res) => {
  try {
    const { email, senha, nome, idade, endereço } = req.body
    const senhaCriptografada = await bcrypt.hash(req.body.senha, 10)
    const user = await prisma.user.create({
      data: {
        email,          
        senha: senhaCriptografada,
        nome,             
        idade,     
        endereço,       
      },
    })
    res.status(201).json(user)
  } catch (error) {
    if (error.code === 'P2002') {
      res.status(409).json({ error: 'E-mail já cadastrado.' })
    } else {
      console.error(error)
      res.status(500).json({ error: 'Erro ao criar usuário.' })
    }
  }
})

// Buscar todos os usuários
app.get('/usuarios', async (req, res) => {
  try {
    const users = await prisma.user.findMany()
    res.status(200).json(users)
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Erro ao buscar usuários.' })
  }
})

// Buscar usuário por ID
app.get('/usuarios/:id_do_usuario', async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id:req.params.id_do_usuario },
    })

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' })
    }
    res.status(200).json(user)
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Erro ao buscar usuário.' })
  }
})

// Atualizar usuário pelo ID
app.put('/usuarios/:id_do_usuario', async (req, res) => {
  try {
    let dadosParaAtualizar = {
      email: req.body.email,
      nome: req.body.nome,
      idade: req.body.idade,
      endereço:req.body.endereço,
    }

    if (req.body.senha) {
      const senhaCriptografada = await bcrypt.hash(req.body.senha, 10)
      dadosParaAtualizar.senha = senhaCriptografada
    }
    
    const user = await prisma.user.update({
      where: { id:req.params.id_do_usuario }, // conversão para número
      data: dadosParaAtualizar,
    })

    res.status(200).json(user)
  } catch (error) {
    console.error(error)
    if (error.code === 'P2025') {
      return res.status(404).json({ error: 'Usuário não encontrado para atualizar.' })
    }
    res.status(500).json({ error: 'Erro ao atualizar usuário.' })
  }
})

// Rota de login
app.post('/login', async (req, res) => {
  try {
    const { email, senha } = req.body

    const user = await prisma.user.findUnique({
      where: { email },
    })

    if (!user) {
      return res.status(401).json({ error: 'E-mail ou senha inválidos' })
    }

    const senhaValida = await bcrypt.compare(senha, user.senha)
    if (!senhaValida) {
      return res.status(401).json({ error: 'E-mail ou senha inválidos' })
    }

    // Gera token JWT
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: '1h',
    })

    res.json({ message: 'Login realizado com sucesso!', token })
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: 'Erro ao realizar login.' })
  }
})

const PORT = 3000
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`)
})
