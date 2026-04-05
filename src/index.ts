import "dotenv/config";
import express, { urlencoded } from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import { router } from "./routes/index.js";
import { setupSwagger } from "./utils/swagger.js";

const app = express();
app.use(cookieParser());
app.use(cors());
app.use(urlencoded({ extended: true }));
app.use(express.json());

setupSwagger(app);

app.use("/api/v1", router);

app.listen(3000, () => {
  console.log("port is listened on the 3000");
});
