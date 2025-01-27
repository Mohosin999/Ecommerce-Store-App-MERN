import User from "../models/user.model.js";

export const signup = async (_req, res) => {
  const { name, email, password } = _req.body;

  try {
    // Check if user already exists
    const user = await User.findOne({ email });

    if (user) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Create new user
    const newUser = await User.create({ name, email, password });

    res.status(201).json({ newUser, message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const login = async (_req, res) => {
  res.send("Login route called");
};

export const logout = async (_req, res) => {
  res.send("Logout route called");
};
