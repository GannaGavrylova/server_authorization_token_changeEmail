import express from "express";
import bcrypt from "bcrypt";
import "dotenv/config";
import authenticateJWT from "./middleware/authenticateJWT.js";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();

const users = [
  {
    id: 1,
    name: "User",
    email: "user@gmail.com",
    password: bcrypt.hashSync("password123", 10), // hash password
  },
];

const port = process.env.PORT || 3333;
const jwtSecret = process.env.JWT_SECRET || "testSecret";
if (!jwtSecret) {
  throw new Error("JWT_SECRET is not defined in environment variables."); // JWT_SECRET не определен в переменных окружения.
}
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.status(200).json(users);
});
// Вход
app.get("/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const user = users.find((u) => u.email === email);
    if (!user) {
      return res.status(404).json({ error: "User is not found" });
    }
    // console.log(user);

    const isPassword = await bcrypt.compare(password, user.password);
    if (!isPassword) {
      return res.status(401).json({ error: "Password invalid" });
    }
    console.log(isPassword);
    //Если почта и пароль введены верно, создаем JWT токен

    const token = jwt.sign(
      { userId: user.id, email: user.email }, // Payload токенa
      jwtSecret, // секрет для подписи
      { expiresIn: "1h" } // время жизни токена
    );
    // отправляем токен клиенту
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
});
// Запрос на изменение email
app.put("/update-email", authenticateJWT, async (req, res) => {
  const { newEmail } = req.body;
  if (!newEmail) {
    return res.status(400).json({ error: "New email is required" });
  }
  try {
    const user = users.find((u) => u.id === req.user.userId);
    if (!user) {
      return res.status(404).json({ error: "User is not found" });
    }
    //проверяем email на уникальность
    const emailExists = users.find((u) => u.email === newEmail);
    if (emailExists) {
      return res.status(400).json({ error: "Email is already in use" });
    }
    console.log(emailExists);

    if (newEmail) user.email = newEmail;
    res.status(200).json({ message: "Email updated successfully" });
  } catch (error) {
    console.log("Error updating email:", error);
    res.status(500).json({ message: " Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port http://localhost:${port}`);
});
