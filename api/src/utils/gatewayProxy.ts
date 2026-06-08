import { Request, Response } from 'express';
import axios, { AxiosError } from 'axios';

interface ProxyRouteOptions {
  timeout?: number;
  transformResponse?: (data: any) => any;
  onNotFound?: (res: Response) => void;
}

/**
 * Helper for proxying requests to the Python gateway
 * Handles common error patterns and response formatting
 */
export const proxyToPythonGateway = async (
  req: Request,
  res: Response,
  gatewayUrl: string,
  options: ProxyRouteOptions = {}
): Promise<void> => {
  const {
    timeout = 10000,
    transformResponse,
    onNotFound
  } = options;

  try {
    const response = await axios.get(gatewayUrl, { timeout });
    const data = transformResponse ? transformResponse(response.data) : response.data;
    res.json(data);
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) {
      if (onNotFound) {
        onNotFound(res);
        return;
      }
      res.status(404).json({ error: 'Resource not found' });
      return;
    }
    res.status(500).json({
      error: 'Gateway request failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
};

/**
 * Helper for POST requests to the Python gateway
 */
export const postToPythonGateway = async (
  req: Request,
  res: Response,
  gatewayUrl: string,
  payload: unknown,
  options: ProxyRouteOptions & { statusOnSuccess?: number } = {}
): Promise<void> => {
  const {
    timeout = 30000,
    transformResponse,
    statusOnSuccess = 200
  } = options;

  try {
    const response = await axios.post(gatewayUrl, payload, { timeout });
    const data = transformResponse ? transformResponse(response.data) : response.data;
    res.status(statusOnSuccess).json(data);
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 404) {
        res.status(404).json({ error: 'Resource not found' });
        return;
      }
      if (error.code === 'ECONNREFUSED') {
        res.status(503).json({
          error: 'Gateway service unavailable',
          details: 'Python gateway is not running'
        });
        return;
      }
    }
    res.status(500).json({
      error: 'Gateway request failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    });
  }
};

/**
 * Standard error handler for axios requests
 */
export const handleAxiosError = (
  res: Response,
  error: unknown,
  context: {
    notFoundMessage?: string;
    errorMessage?: string;
  } = {}
): void => {
  const {
    notFoundMessage = 'Resource not found',
    errorMessage = 'Request failed'
  } = context;

  if (axios.isAxiosError(error)) {
    if (error.response?.status === 404) {
      res.status(404).json({ error: notFoundMessage });
      return;
    }
    if (error.code === 'ECONNREFUSED') {
      res.status(503).json({
        error: 'Service unavailable',
        details: 'Backend service is not running'
      });
      return;
    }
  }

  res.status(500).json({
    error: errorMessage,
    details: error instanceof Error ? error.message : 'Unknown error'
  });
};
