import { COOKIE_NAME } from "@shared/const";
import { getSessionCookieOptions } from "./_core/cookies";
import { systemRouter } from "./_core/systemRouter";
import { publicProcedure, router, protectedProcedure } from "./_core/trpc";
import { z } from "zod";
import { analyzeUrl } from "./detector";
import { analyzeUrlPremium } from "./detector-v2";
import { createUrlScan, getUserUrlScans } from "./db";

export const appRouter = router({
  system: systemRouter,
  auth: router({
    me: publicProcedure.query(opts => opts.ctx.user),
    logout: publicProcedure.mutation(({ ctx }) => {
      const cookieOptions = getSessionCookieOptions(ctx.req);
      ctx.res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: -1 });
      return {
        success: true,
      } as const;
    }),
  }),

  urlAnalysis: router({
    analyze: protectedProcedure
      .input(z.object({ url: z.string().min(1, "URL is required") }))
      .mutation(async ({ input, ctx }) => {
        const result = analyzeUrl(input.url);

        try {
          await createUrlScan(
            ctx.user.id,
            result.url,
            result.threatLevel,
            result.riskScore,
            result.reasons,
            result.triggeredRules
          );
        } catch (error) {
          console.error("Failed to save scan to database:", error);
        }

        return result;
      }),

    analyzePremium: protectedProcedure
      .input(z.object({ url: z.string().min(1, "URL is required") }))
      .mutation(async ({ input, ctx }) => {
        const result = await analyzeUrlPremium(input.url);

        try {
          await createUrlScan(
            ctx.user.id,
            result.url,
            result.threatLevel,
            result.finalScore,
            result.reasons,
            result.triggeredRules
          );
        } catch (error) {
          console.error("Failed to save scan to database:", error);
        }

        return result;
      }),

    history: protectedProcedure
      .input(
        z.object({
          limit: z.number().min(1).max(100).default(50),
          offset: z.number().min(0).default(0),
        })
      )
      .query(async ({ input, ctx }) => {
        return getUserUrlScans(ctx.user.id, input.limit, input.offset);
      }),
  }),
});

export type AppRouter = typeof appRouter;
