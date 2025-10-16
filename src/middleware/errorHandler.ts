import { NextFunction, Request, Response } from "express";

const errorHandler = (
  err: any,
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { message, statusCode, stack } = err;
  res
    .status(statusCode)
    .json({
      message,
      ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
    });
};
export default errorHandler;
