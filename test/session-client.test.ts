import { SRPParameters } from "../src/parameters";
import { SRPRoutines } from "../src/routines";
import { SRPClientSession } from "../src/session-client";
import { generateRandomBigInt, generateRandomString } from "../src/utils";
import { test } from "./tests";

test("#ParameterValidation1 Null/Undefined Identity", async (t) => {
  const session = new SRPClientSession(new SRPRoutines(new SRPParameters()));
  await t.rejects(
    async () => session.step1(null!, await generateRandomString(16)),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation1 Empty Identity", async (t) => {
  const session = new SRPClientSession(new SRPRoutines(new SRPParameters()));
  await t.rejects(
    async () => session.step1("", await generateRandomString(16)),
    /empty/i,
  );
  t.end();
});

test("#ParameterValidation1 Null/Undefined password", async (t) => {
  const session = new SRPClientSession(new SRPRoutines(new SRPParameters()));
  await t.rejects(
    async () => session.step1(await generateRandomString(16), null!),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation2 All correct", async (t) => {
  const session = await new SRPClientSession(
    new SRPRoutines(new SRPParameters()),
  ).step1("a", "b");
  await t.doesNotReject(async () =>
    session.step2(
      await generateRandomBigInt(16),
      await generateRandomBigInt(16),
    ),
  );
  t.end();
});

test("#ParameterValidation2 Null/Undefined salt", async (t) => {
  const session = await new SRPClientSession(
    new SRPRoutines(new SRPParameters()),
  ).step1("a", "b");
  await t.rejects(
    async () => session.step2(null!, await generateRandomBigInt(16)),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation2 Null/Undefined B", async (t) => {
  const session = await new SRPClientSession(
    new SRPRoutines(new SRPParameters()),
  ).step1("a", "b");
  await t.rejects(
    async () => session.step2(await generateRandomBigInt(16), null!),
    /null/i,
  );
  t.end();
});

test("#ParameterValidation3 All correct", async (t) => {
  const session = await (
    await new SRPClientSession(new SRPRoutines(new SRPParameters())).step1(
      "a",
      "b",
    )
  ).step2(await generateRandomBigInt(16), await generateRandomBigInt(16));
  // It rejects because the fake values don't allow the verification to work
  await t.rejects(
    async () => session.step3(await generateRandomBigInt(16)),
    /bad server/i,
  );
  t.end();
});

test("#ParameterValidation3 Null/Undefined M2", async (t) => {
  const session = await (
    await new SRPClientSession(new SRPRoutines(new SRPParameters())).step1(
      "a",
      "b",
    )
  ).step2(await generateRandomBigInt(16), await generateRandomBigInt(16));
  await t.rejects(() => session.step3(null!), /null/i);
  t.end();
});
