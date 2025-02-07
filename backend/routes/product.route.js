import express from "express";
import { getAllProducts } from "./../controllers/product.controller.js";
import { adminRoute, protectRoute } from "./../middleware/auth.middleware";

const router = express.Router();

router.get("/", protectRoute, adminRoute, getAllProducts);
router.get("/featured", getFeaturedProducts);

export default router;
