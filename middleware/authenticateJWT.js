import jwt from "jsonwebtoken";

export default function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer")) {
    const token = authHeader.split(" ")[1]; // Извлекаем токен

    // Проверяем токен
    jwt.verify(token, process.env.JWT_SECRET, (err, data) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "Forbidden: invalid or expired token " });
      }
      console.log("Authorization header: ", authHeader);
      req.user = data;
      next();
    });
  } else {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }
}