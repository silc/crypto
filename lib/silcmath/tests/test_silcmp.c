/* SILC MP API tests */

#include "silccrypto.h"

/* Test results */

const char *num =
"12345678901234560982730284776329476199876349211974638723947362976";
const char *num16 =
"1E02BC1E9785872282806CD2F75C9C037D185B159C6BF928C4FAA0";
const char *num2 =
"111100000001010111100000111101001011110000101100001110010001010000010100000000110110011010010111101110101110010011100000000110111110100011000010110110001010110011100011010111111100100101000110001001111101010100000";

/* Add */
const char *numplusnum =
"24691357802469121965460569552658952399752698423949277447894725952";

/* Div UI */
const char *numdiv3 =
"8230452600823040655153523184219650799917566141316425815964908650";

/* Sub */
const char *numsubnum =
"16460905201646081310307046368439301599835132282632851631929817302";

/* Mul */
const char *nummulnum =
"406442100086368525205432595008864090782598685309019707370392150100104880233122729099893851398423765038006246640472147376718021504";

/* Pow 9 */
const char *numpow9 =
"30268310490095248136374442593960735340043215092235037140910676088144"
"35058076907508346521934800012973063581682693747048031478666348478106"
"44683456845011455064024666852414062817276759918308447029021294253178"
"33315247099510816723345641886025287379547228426885091818754699607678"
"21224366024226166683969708998047098297710016071652606735552588847286"
"34852468216958922270511264725208810741994612375692799609732354209956"
"40819760982889468862162693712340583165661711574919011669535502396672"
"40312267464770558012687533541147373851940126476804050825510259049427"
"65748814943077966488645043069629580317025213490538353938548940375954"
"82427393090269404947604548936674976991676788833885882090558205985379"
"89472452919247278891609709393833528917324368765083583279471748113886"
"79206753418608834013097102872543865922235479608256858601874978505022"
"00266244958174441947434256912448253544273297263228373429056333060573"
"16358665005119352040979366412364735432045274742825321120330834699236"
"76412760737356102356966921386940229431060689424016835315932709079195"
"30189129058275516394261019070663759164289157669667381917985720833067"
"7211314718626801218364761769796339230934500991496997725669208457478144";

/* Pow 99, SHA1 digest */
const char *numpow99 =
"E8BB0A6A5D56133A25F8B640F63E65431179385B";

/* Mod */
const char *nummod =
"406442100086368525205432595008864090782598685309019707370392150100104880233122729099893851398423765038006246640472147376718021504";

/* Sqrt */
const char *numsqrt =
"20160409224179169057262993915549091951057267453046056852604825434";

/* Exptmod */
const char *numexptmod =
"173429534539409901711356454898127569290532192909973256589717126062627843574169918766243051602605611974408600605387662387616633336";

/* Modinv */
const char *numinv =
"148304443647050524986847521354145653720804753630979716002896148087342832655697121528033378180741078274204970432436357573430185481";

/* AND */
const char *numand =
"13575514895142195405643119649905581499134975342931066988498846464";

/* OR */
const char *numor =
"406442100086368525205432595008864090782598685309019707370392150106689774562159702751513725664067275489928538750587137240824000475";

/* XOR */
const char *numxor =
"406442100086368525205432595008864090782598685309019707370392150093114259667017507345870606014161693990793563407656070252325154011";

int main(int argc, char **argv)
{
  SilcBool success = FALSE;
  unsigned char i[65535], r[65535], hash[20];
  SilcMPInt mp1, mp2, mp3, mp4;
  SilcUInt32 ui;
  SilcHash sha1;

  silc_runtime_init();

  if (argc > 1 && !strcmp(argv[1], "-d")) {
    silc_log_debug(TRUE);
    silc_log_quick(TRUE);
    silc_log_debug_hexdump(TRUE);
    silc_log_set_debug_string("*mp*,*math*,*tfm*,*tma*,*gmp*,*stack*");
  }

  silc_hash_alloc("sha1", &sha1);

  if (!silc_mp_init(&mp1))
    goto err;
  if (!silc_mp_init(&mp2))
    goto err;
  if (!silc_mp_init(&mp3))
    goto err;
  if (!silc_mp_init(&mp4))
    goto err;

  SILC_LOG_DEBUG(("Set number: %s", num));
  silc_mp_set_str(&mp1, num, 10);

  SILC_LOG_DEBUG(("Get number, base 10"));
  if (!silc_mp_get_str(r, &mp1, 10))
    goto err;
  SILC_LOG_DEBUG(("Number: %s", r));
  if (strcmp(num, r))
    goto err;


  SILC_LOG_DEBUG(("Get number, base 16"));
  if (!silc_mp_get_str(r, &mp1, 16))
    goto err;
  SILC_LOG_DEBUG(("Number: %s", r));
  if (strcmp(num16, r))
    goto err;

  SILC_LOG_DEBUG(("Get number, base 2"));
  if (!silc_mp_get_str(r, &mp1, 2))
    goto err;
  SILC_LOG_DEBUG(("Number: %s", r));
  if (strcmp(num2, r))
    goto err;


  SILC_LOG_DEBUG(("Get size in base 2"));
  ui = silc_mp_sizeinbase(&mp1, 2);
  SILC_LOG_DEBUG(("Size: %d (should be %d)", ui, strlen(num2)));
  if (ui != strlen(num2))
    goto err;

  SILC_LOG_DEBUG(("Get size in base 16"));
  ui = silc_mp_sizeinbase(&mp1, 16);
  SILC_LOG_DEBUG(("Size: %d (should be %d)", ui, strlen(num16)));
  if (ui != strlen(num16))
    goto err;

  SILC_LOG_DEBUG(("Get size in base 10"));
  ui = silc_mp_sizeinbase(&mp1, 10);
  SILC_LOG_DEBUG(("Size: %d (should be %d)", ui, strlen(num)));
  if (ui != strlen(num))
    goto err;


  SILC_LOG_DEBUG(("Set integer"));
  if (!silc_mp_set(&mp2, &mp1))
    goto err;
  SILC_LOG_DEBUG(("Compare integers"));
  if (silc_mp_cmp(&mp1, &mp2) != 0)
    goto err;
  SILC_LOG_DEBUG(("Match"));

  SILC_LOG_DEBUG(("Set small UI integer"));
  if (!silc_mp_set_ui(&mp2, 99999))
    goto err;
  SILC_LOG_DEBUG(("Compare integers"));
  if (silc_mp_cmp_ui(&mp2, 99999) != 0)
    goto err;
  SILC_LOG_DEBUG(("Match"));


  SILC_LOG_DEBUG(("Get UI"));
  ui = silc_mp_get_ui(&mp1);
  SILC_LOG_DEBUG(("UI: %lu", ui));
  if (ui != 683997856)
    goto err;


  SILC_LOG_DEBUG(("Add %s + %s", num, num));
  if (!silc_mp_add(&mp3, &mp1, &mp1))
    goto err;
  if (!silc_mp_get_str(r, &mp3, 10))
    goto err;
  SILC_LOG_DEBUG((" = %s", r));
  if (strcmp(r, numplusnum))
    goto err;

  silc_mp_uninit(&mp1);
  if (!silc_mp_init(&mp1))
    goto err;

  SILC_LOG_DEBUG(("Div %s / 3", r));
  if (!silc_mp_div_ui(&mp4, &mp3, 3))
    goto err;
  if (!silc_mp_get_str(i, &mp4, 10))
    goto err;
  SILC_LOG_DEBUG((" = %s", i));
  if (strcmp(i, numdiv3))
    goto err;

  SILC_LOG_DEBUG(("Sub %s - %s", r, i));
  if (!silc_mp_sub(&mp4, &mp3, &mp4))
    goto err;
  if (!silc_mp_get_str(i, &mp4, 10))
    goto err;
  SILC_LOG_DEBUG((" = %s", i));
  if (strcmp(i, numsubnum))
    goto err;

  SILC_LOG_DEBUG(("Mul %s * %s", r, i));
  if (!silc_mp_mul(&mp4, &mp3, &mp4))
    goto err;
  if (!silc_mp_get_str(i, &mp4, 10))
    goto err;
  SILC_LOG_DEBUG((" = %s", i));
  if (strcmp(i, nummulnum))
    goto err;

  SILC_LOG_DEBUG(("Pow %s ^ 9", i));
  if (!silc_mp_pow_ui(&mp3, &mp4, 9))
    goto err;
  if (!silc_mp_get_str(r, &mp3, 10))
    goto err;
  SILC_LOG_DEBUG((" = %s", r));
  if (strcmp(r, numpow9))
    goto err;

  SILC_LOG_DEBUG(("Pow %s ^ 99", i));
  if (!silc_mp_pow_ui(&mp3, &mp4, 99))
    goto err;
  if (!silc_mp_get_str(i, &mp3, 10))
    goto err;
  silc_hash_make(sha1, i, strlen(i), hash);
  silc_data2hex(hash, 20, i, sizeof(i));
  SILC_LOG_DEBUG(("  digest = %s", i));
  if (strcmp(i, numpow99))
    goto err;

  SILC_LOG_DEBUG(("Mod %s", r));
  if (!silc_mp_mod(&mp3, &mp4, &mp3))
    goto err;
  if (!silc_mp_get_str(r, &mp3, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", r));
  if (strcmp(r, nummod))
    goto err;

  SILC_LOG_DEBUG(("Sqrt %s", r));
  if (!silc_mp_sqrt(&mp4, &mp3))
    goto err;
  if (!silc_mp_get_str(i, &mp4, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", i));
  if (strcmp(i, numsqrt))
    goto err;

  if (!silc_mp_add_ui(&mp3, &mp3, 1))
    goto err;
  if (!silc_mp_get_str(r, &mp3, 10))
    goto err;
  SILC_LOG_DEBUG(("Exptmod %s ^ %s mod %s", i, i, r));
  if (!silc_mp_pow_mod(&mp1, &mp4, &mp4, &mp3))
    goto err;
  if (!silc_mp_get_str(i, &mp1, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", i));
  if (strcmp(i, numexptmod))
    goto err;

  SILC_LOG_DEBUG(("GCD"));
  if (!silc_mp_gcd(&mp2, &mp1, &mp3))
    goto err;
  if (!silc_mp_get_str(i, &mp2, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", i));
  if (silc_mp_cmp_ui(&mp2, 1) != 0)
    goto err;

  SILC_LOG_DEBUG(("Modinv"));
  if (!silc_mp_modinv(&mp2, &mp1, &mp3))
    goto err;
  if (!silc_mp_get_str(i, &mp2, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", i));
  if (strcmp(i, numinv))
    goto err;

  SILC_LOG_DEBUG(("AND"));
  if (!silc_mp_and(&mp1, &mp4, &mp3))
    goto err;
  if (!silc_mp_get_str(i, &mp1, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", i));
  if (strcmp(i, numand))
    goto err;

  SILC_LOG_DEBUG(("OR"));
  if (!silc_mp_or(&mp1, &mp4, &mp3))
    goto err;
  if (!silc_mp_get_str(i, &mp1, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", i));
  if (strcmp(i, numor))
    goto err;

  SILC_LOG_DEBUG(("XOR"));
  if (!silc_mp_xor(&mp1, &mp4, &mp3))
    goto err;
  if (!silc_mp_get_str(i, &mp1, 10))
    goto err;
  SILC_LOG_DEBUG(("  = %s", i));
  if (strcmp(i, numxor))
    goto err;


  silc_mp_uninit(&mp1);
  silc_mp_uninit(&mp2);
  silc_mp_uninit(&mp3);
  silc_mp_uninit(&mp4);

  silc_hash_free(sha1);

  success = TRUE;

 err:
  SILC_LOG_DEBUG(("Testing was %s", success ? "SUCCESS" : "FAILURE"));
  fprintf(stderr, "Testing was %s\n", success ? "SUCCESS" : "FAILURE");

  silc_runtime_uninit();

  return !success;
}
