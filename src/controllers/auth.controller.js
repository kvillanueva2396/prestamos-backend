const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const pool = require('../db')

const login = async (req, res) => {
	const { username, password } = req.body

	// Validar que vengan los datos
	if (!username || !password) {
		return res.status(400).json({ error: 'Usuario y contraseña son requeridos' })
	}

	try {
		// Buscar el usuario en la BD
		const result = await pool.query('SELECT * FROM users WHERE username = $1', [username])

		if (result.rows.length === 0) {
			return res.status(401).json({ error: 'Credenciales inválidas' })
		}

		const user = result.rows[0]

		// Comparar contraseña ingresada con el hash guardado
		const passwordMatch = await bcrypt.compare(password, user.password_hash)

		if (!passwordMatch) {
			return res.status(401).json({ error: 'Credenciales inválidas' })
		}

		const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
			expiresIn: '5minutes',
		})

		return res.status(200).json({
			message: 'Login exitoso',
			token,
		})
	} catch (err) {
		console.error('Error en login:', err.message)
		return res.status(500).json({ error: 'Error interno del servidor' })
	}
}

module.exports = { login }
