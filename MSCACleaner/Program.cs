using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using GK.MSCAWrapper;
using System.Data;
using log4net;
using System.Runtime.InteropServices;

// configure log4net with app.config
[assembly: log4net.Config.XmlConfigurator]

namespace GK.CACleaner
{
    static class Program
    {
        enum Command { listColumns, cleanDuplicates, cleanDuplicatesDry, repairRevocation, repairAllRevocations, repairAllRevocationsDry, repairIssuedCerts, repairIssuedCertsDry, listCertTemplates };

        /// <summary>
        /// Main entry point for the GK.CACleaner application. Searches for duplicate certificates
        /// in the Certificate Services databases and revokes them except for the newest.
        /// Two certificates are duplicates if they have the same subject.
        /// </summary>
        /// <param name="args">No command line arguments are currently supported</param>
        static void Main(string[] args)
        {
#if DEBUG
                // The program only works if the MS CA runs in the same domain as this
                // program. When debugging, a remote debugger should be used
            Console.WriteLine("Waiting for keypress to attach debugger");
            Console.ReadKey();
#endif
            if (args.Length < 2 || !(new char[] { '-', '/' }).Contains(args[0][0]))   // first parameter starts with - or /)
            {
                printUsage("First argument must be a command prefixed with -");
                return;
            }

            Command order;
            if (!Enum.TryParse<Command>(args[0].Substring(1), out order))
            {
                printUsage("Unknown command: " + args[0]);
                return;
            }

            try
            {
                string strMsCAConnectionstring = args.Last();
                CertificateServices msca = new CertificateServices(strMsCAConnectionstring);

                switch (order)
                {
                    case Command.cleanDuplicates:
                    case Command.cleanDuplicatesDry:
                        cleanDuplicates(msca, Command.cleanDuplicates == order);
                        break;
                    case Command.listColumns:
                        ILog log = LogManager.GetLogger("GK.CACleaner.Console.listColumns");
                        log.Info("Listing columns...");
                        foreach (CertColumn column in msca.columns)
                            log.Info("Column: " + column.name);
                        log.Info("All columns listed");
                        break;
                    case Command.repairRevocation:
                        if (args.Length != 3)
                        {
                            printUsage("repairRevocation expects exactly three parameters, but you gave " + args.Length + " parameters.");
                            return;
                        }
                        int iRequestID = int.Parse(args[1]);
                        repairRevocation(msca, iRequestID);
                        break;
                    case Command.repairAllRevocations:
                    case Command.repairAllRevocationsDry:
                        if (args.Length != 3)
                        {
                            printUsage("repairAllRevocations expects exactly three parameters, but you gave " + args.Length + " parameters.");
                            return;
                        }
                        DateTime datEnd = DateTime.Parse(args[1]);
                        repairAllRevocations(msca, datEnd, Command.repairAllRevocations == order);
                        break;
                    case Command.repairIssuedCerts:
                    case Command.repairIssuedCertsDry:
                        if (args.Length != 3)
                        {
                            printUsage("repairIssuedCerts expects exactly three parameters, but you gave " + args.Length + " parameters.");
                            return;
                        }
                        DateTime datIssuedEnd = DateTime.Parse(args[1]);
                        repairAllIssuedCerts(msca, datIssuedEnd, Command.repairIssuedCerts == order);
                        break;
                    case Command.listCertTemplates:
                        listAllADCertificateTemplates();
                        break;
                    default:
                        throw new NotImplementedException("The command " + order + " is not yet implemented.");
                }
            }
            catch (COMException cEx)
            {
                LogManager.GetLogger("GK.CACleaner.Console").Fatal("COM Exception while executing command.", cEx);
                throw;
            }

            LogManager.GetLogger("GK.CACleaner.Console").Info("Program executed successfully");
        }

        static void printUsage(string errormessage)
        {
            LogManager.GetLogger("GK.CACleaner.Console.printUsage").Error("Command executed with invalid parameters");

            Console.WriteLine();
            Console.WriteLine("Copyright (c) 2017 Glueck & Kanja Consulting AG");
            Console.WriteLine();
            Console.WriteLine("Error: " + errormessage);
            Console.WriteLine();
            Console.WriteLine("USAGE: MSCACleaner.exe -COMMAND CONNECTIONSTRING");
            Console.WriteLine("USAGE: MSCACleaner.exe -repairRevocation REQUESTID CONNECTIONSTRING");
            Console.WriteLine("USAGE: MSCACleaner.exe -repairAllRevocations[Dry] ENDDATE CONNECTIONSTRING");
            Console.WriteLine();
            Console.WriteLine("COMMAND list:");
            Console.WriteLine("    -listColumns        Prints all columns available in the MS CA Database");
            Console.WriteLine();
            Console.WriteLine("    -cleanDuplicates    Revokes duplicate valid certificates (certs with same");
            Console.WriteLine("                        subject), while keeping the youngest");
            Console.WriteLine();
            Console.WriteLine("    -cleanDuplicatesDry Same as -cleanDuplicates, but the results are only");
            Console.WriteLine("                        logged, no certificate is actually revoked");
            Console.WriteLine();
            Console.WriteLine("    -repairRevocation REQUESTID");
            Console.WriteLine("                        Repairs a revocation database entry assigned to the");
            Console.WriteLine("                        wrong CA certificate by deleting, reimporting and");
            Console.WriteLine("                        re-revoking the certificate with the given REQUESTID");
            Console.WriteLine();
            Console.WriteLine("    -repairAllRevocations ENDDATE");
            Console.WriteLine("    -repairAllRevocationsDry ENDDATE");
            Console.WriteLine("                        Repairs revocation database entries assigned to the");
            Console.WriteLine("                        wrong CA certificate by deleting, reimporting and");
            Console.WriteLine("                        re-revoking these certificates.");
            Console.WriteLine("                        This procedure applies to all revoked certificates");
            Console.WriteLine("                        issued before ENDDATE.");
            Console.WriteLine("                        The dry variation will not actually change the");
            Console.WriteLine("                        database, but only log what it would do.");
            Console.WriteLine();
            Console.WriteLine("    -repairIssuedCerts ENDDATE");
            Console.WriteLine("    -repairIssuedCertsDry ENDDATE");
            Console.WriteLine("                        Repairs a database entries assigned to the");
            Console.WriteLine("                        wrong CA certificate by deleting and reimporting");
            Console.WriteLine("                        these certificates.");
            Console.WriteLine("                        This procedure applies to all non-revoked and");
            Console.WriteLine("                        not expired certificates issued before ENDDATE.");
            Console.WriteLine("                        The dry variation will not actually change the");
            Console.WriteLine("                        database, but only log what it would do."); 
            Console.WriteLine();
            Console.WriteLine("CONNECTIONSTRING specifies the Microsoft Certificate Services Server to connect");
            Console.WriteLine("                 to. Use the syntax COMPUTERNAME\\CANAME");           
            Console.WriteLine();           
        }

        /// <summary>
        /// Searches for certificate duplicates (certs with same subject) and revokes all except
        /// the youngest for each subject.
        /// </summary>
        /// <param name="msca">The MS CA to connect to</param>
        /// <param name="fRevokeCerts">Shall the certificates really be revoked or is it a dry run only?</param>
        static void cleanDuplicates(CertificateServices msca, bool fRevokeCerts)
        {
            ILog log = LogManager.GetLogger("GK.CACleaner.Console.cleanDuplicates");
            log.Info("Starting to clean Certificate Services database...");

            DataTable dtCerts = msca.queryIssuedCertificates(
                msca.columns.Where(col => col.name == "DistinguishedName" ||
                                            col.name == "SerialNumber" ||
                                            col.name == "NotAfter" ||
                                            col.name == "NotBefore").ToList());

            log.Info("Found " + dtCerts.Rows.Count + " certificates in the database (including expired).");

            // a dictionary of subjects, for each of which a linked list is stored
            // and each of these lists will contain a Serial/NotBefore pair for
            // every certificate with this subject
            IDictionary<String, ICollection<KeyValuePair<string, DateTime>>>
                dictCerts = new Dictionary<string, ICollection<KeyValuePair<string, DateTime>>>(10000);

            foreach (DataRow drCert in dtCerts.Rows)
                if (Convert.ToDateTime(drCert["NotAfter"]).CompareTo(DateTime.UtcNow) > 0) // only non-expired certs
                {
                    if (!dictCerts.Keys.Contains(drCert["DistinguishedName"].ToString()))
                        dictCerts[drCert["DistinguishedName"].ToString()] = new LinkedList<KeyValuePair<string, DateTime>>();

                    dictCerts[drCert["DistinguishedName"].ToString()].Add(
                        new KeyValuePair<string, DateTime>(drCert["SerialNumber"].ToString(), Convert.ToDateTime(drCert["NotBefore"])));
                }

            log.Info("All certificate serials acquired and sorted. There are " + dictCerts.Count + " unique subjects (excluding expired).");

            ILog revLog = LogManager.GetLogger("GK.CACleaner.Console.cleanDuplicates.Revocation");
            foreach (string subject in dictCerts.Keys)
                if (dictCerts[subject].Count == 1)      // unique certificate
                {
                    KeyValuePair<string, DateTime> pairCert = dictCerts[subject].First();
                    revLog.Debug("UNIQUE: Subject=\"" + subject + "\", serial=" + pairCert.Key + ", creation date=" + pairCert.Value.ToString());
                }
                else
                {
                    revLog.Info("There are " + dictCerts[subject].Count.ToString()
                        + " certificates with the subject \"" + subject + "\", revoking the oldest...");
                    string strYoungestSerial = string.Empty;
                    DateTime datYoungestCert = DateTime.MinValue;

                    // find youngest certificate
                    foreach (KeyValuePair<string, DateTime> pairCert in dictCerts[subject])
                        if (pairCert.Value.CompareTo(datYoungestCert) > 0)  // current cert is younger than the youngest cert
                        {
                            strYoungestSerial = pairCert.Key;
                            datYoungestCert = pairCert.Value;
                        }

                    // revoke all certificates except youngest
                    revLog.Info("KEEP: Subject=\"" + subject + "\", serial=" + strYoungestSerial + ", creation date=" + datYoungestCert.ToString());
                    foreach (KeyValuePair<string, DateTime> pairCert in dictCerts[subject])
                        if (pairCert.Key != strYoungestSerial)
                        {
                            DateTime datRevocation = DateTime.UtcNow;
                            string strCertInfo = "Subject=\"" + subject + "\", serial=" + pairCert.Key + ", creation date=" + pairCert.Value.ToString() + ", revocation date=" + datRevocation.ToString();
                            if (fRevokeCerts)
                            {
                                msca.revokeCertificate(pairCert.Key, CertificateServices.RevocationReason.SUPERSEDED, datRevocation);
                                revLog.Info("REVOKE: " + strCertInfo);
                            }
                            else
                                revLog.Info("DRY-REVOKE: " + strCertInfo);
                        }
                }

            //var validCerts = (
            //    from System.Data.DataRow drCert in dtCerts.Rows
            //    where Convert.ToDateTime(drCert["NotAfter"]).CompareTo(DateTime.UtcNow) > 0 // only non-expired certs
            //    select new KeyValuePair <string,KeyValuePair<DateTime,String>> // create a triple Subject/NotBefore/SerialNumber
            //        ( drCert["DistinguishedName"].ToString(),
            //        new KeyValuePair<DateTime,String>
            //            ( Convert.ToDateTime(drCert["NotBefore"]),
            //              drCert["SerialNumber"].ToString())
            //        )
            //    )
            //        .GroupBy(;

            // msca.revokeCertificate(serialXChange, CertificateServices.RevocationReason.SUPERSEDED, DateTime.UtcNow.AddYears(-1));

        }

        private static void repairRevocation(CertificateServices msca, int iRequestID)
        {
            ILog log = LogManager.GetLogger("GK.CACleaner.Console.repairRevocation.SingleRevocation");
            log.Info("Starting to repair certificate with Request ID " + iRequestID +  "...");

            try
            {
                DataRow drBrokenCertificate = msca.findCertificate(iRequestID, msca.columns.Where(col => 
                                                                        col.name == "RequestID" ||
                                                                        col.name == "RawCertificate" ||
                                                                        col.name == "Request.RevokedEffectiveWhen" ||
                                                                        col.name == "Request.RevokedReason" ||
                                                                        col.name == "SerialNumber").ToArray());

                repairRevokedCertificate(msca, drBrokenCertificate, true);

                log.Info("Certificate was repaired");
            }
            catch (System.Runtime.InteropServices.ExternalException eex)
            {
                log.Error("ExternalException with ErrorCode " + eex.ErrorCode + " has occurred when repairing a certificate", eex);
                throw;
            }
            catch (Exception ex)
            {
                log.Error("Error repairing certificate", ex);
                throw;
            }
        }

        private static void repairAllRevocations(CertificateServices msca, DateTime datEnd, bool fModifyDatabase)
        {
            ILog log = LogManager.GetLogger("GK.CACleaner.Console.repairRevocation.AllRevocations");
            log.Info("Starting to repair revocations for certificates issued before " + datEnd + " " + (fModifyDatabase?"[MODIFY RUN]":"[DRY RUN]"));

            DataTable dtCerts;

            try
            {
                dtCerts = msca.queryCertificates(
                    new IteratorRestriction(new CertQueryRestriction[] {
                        new SingleValueRestriction(datEnd, msca.columns.Single(col => col.name == "NotBefore")) { filterOperator = SingleValueRestriction.ComparisonOperator.LowerThan },
                        new SingleValueRestriction(CertificateServices.RequestDisposition.Revoked, msca.columns.Single(col => col.name == "Request.Disposition")),
                        new SingleValueRestriction(DateTime.UtcNow, msca.columns.Single(col => col.name == "NotAfter")) { filterOperator = SingleValueRestriction.ComparisonOperator.GreaterThan }
                    }),
                    msca.columns.Where(col =>
                                    col.name == "RequestID" ||
                                    col.name == "RawCertificate" ||
                                    col.name == "Request.RevokedEffectiveWhen" ||
                                    col.name == "Request.RevokedReason" ||
                                    col.name == "SerialNumber"
                                   ).ToArray());
            }
            catch (System.Runtime.InteropServices.ExternalException eex)
            {
                log.Fatal("ExternalException with ErrorCode " + eex.ErrorCode + " has occurred when querying revoked certificates", eex);
                throw;
            }
            catch (Exception ex)
            {
                log.Fatal("Error querying revoked certificates", ex);
                throw;
            }

            if (null == dtCerts)
            {
                log.Info("No revoked certificates found that have been issued before " + datEnd + " and haven't expired yet");
                return;
            }

            log.Info("Found " + dtCerts.Rows.Count + " revoked certificates in the database issued before " + datEnd + ".");

            foreach (DataRow drRevokedCertificate in dtCerts.Rows)
            {
                log4net.ThreadContext.Properties.Clear();

                try
                {
                    repairRevokedCertificate(msca, drRevokedCertificate, fModifyDatabase);
                    log.Info("Successfully repaired a certificate");
                }
                catch (System.Runtime.InteropServices.ExternalException eex)
                {
                    log.Error("ExternalException with ErrorCode " + eex.ErrorCode + " has occurred when repairing a certificate. Proceeding with other certificates...", eex);
                }
                catch (Exception ex)
                {
                    log.Error("Error repairing a certificate. Proceeding with other certificates...", ex);
                }
            }
        }

        private static ILog _logRevocationWorker;
        private static ILog logRevocationWorker
        {
            get
            {
                if (null == _logRevocationWorker)
                    _logRevocationWorker = LogManager.GetLogger("GK.CACleaner.Console.repairRevocation.Worker");
                return _logRevocationWorker;
            }
        }

        /// <summary>
        /// Repairs the MS CA database entry of a revoked certificate that is assigned to the wrong CA certificate
        /// </summary>
        /// <param name="drBrokenCertificate">Columns should comprise: RequestID, RawCertificate, Request.RevokedEffectiveWhen, Request.RevokedReason, SerialNumber</param>
        private static void repairRevokedCertificate(CertificateServices msca, DataRow drBrokenCertificate, bool fModifyDatabase)
        {
            int iRequestID = (int)drBrokenCertificate["RequestID"];
            log4net.ThreadContext.Properties["RequestID.Old"] = iRequestID;
            DateTime datRevocation = (DateTime)drBrokenCertificate["Request.RevokedEffectiveWhen"];
            log4net.ThreadContext.Properties["Request.RevokedEffectiveWhen"] = datRevocation;
            CertificateServices.RevocationReason iRevocationReason = (CertificateServices.RevocationReason)drBrokenCertificate["Request.RevokedReason"];
            log4net.ThreadContext.Properties["Request.RevokedReason"] = iRevocationReason;
            string sSerial = drBrokenCertificate["SerialNumber"].ToString();
            log4net.ThreadContext.Properties["SerialNumber"] = sSerial;
            string sCertificate = (string)drBrokenCertificate["RawCertificate"];

            logRevocationWorker.Debug("Certificate (Serial " + sSerial + ", size " + sCertificate.Length + " bytes) was revoked on " + datRevocation + " because of the reason: " + iRevocationReason);

            if (logRevocationWorker.IsDebugEnabled)
            {
                System.Security.Cryptography.X509Certificates.X509Certificate2 cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    System.Text.Encoding.ASCII.GetBytes(sCertificate)
                );
                logRevocationWorker.Debug("Certificate decoded with subject \"" + cert.Subject + "\"");
            }

            if (fModifyDatabase)
            {
                msca.deleteCertificateRow(iRequestID);

                logRevocationWorker.Debug("Certificate was deleted from database");

                try
                {
                    int iNewRequestID = msca.importCertificate(sCertificate);
                    log4net.ThreadContext.Properties["RequestID.New"] = iNewRequestID;
                }
                catch (Exception ex)
                {
                    _logRevocationWorker.Error("Could not re-import certificate. RawCertificate:\n" + sCertificate, ex);
                    throw;
                }

                logRevocationWorker.Debug("Certificate was reimported into database");

                msca.revokeCertificate(sSerial, iRevocationReason, datRevocation);

                logRevocationWorker.Debug("Certificate was revoked again");
            }
        }

        private static void repairAllIssuedCerts(CertificateServices msca, DateTime datIssuedEnd, bool fModifyDatabase)
        {
            ILog log = LogManager.GetLogger("GK.CACleaner.Console.repairIssued.All");
            log.Info("Starting to repair certificates issued before " + datIssuedEnd + " " + (fModifyDatabase ? "[MODIFY RUN]" : "[DRY RUN]"));

            DataTable dtCerts;

            try
            {
                dtCerts = msca.queryCertificates(
                    new IteratorRestriction(new CertQueryRestriction[] {
                        new SingleValueRestriction(datIssuedEnd, msca.columns.Single(col => col.name == "NotBefore")) { filterOperator = SingleValueRestriction.ComparisonOperator.LowerThan },
                        new SingleValueRestriction(CertificateServices.RequestDisposition.Issued, msca.columns.Single(col => col.name == "Request.Disposition")),
                        new SingleValueRestriction(DateTime.UtcNow, msca.columns.Single(col => col.name == "NotAfter")) { filterOperator = SingleValueRestriction.ComparisonOperator.GreaterThan }
                    }),
                    msca.columns.Where(col =>
                                    col.name == "RequestID" ||
                                    col.name == "RawCertificate" ||
                                    col.name == "SerialNumber"
                                   ).ToArray());
            }
            catch (System.Runtime.InteropServices.ExternalException eex)
            {
                log.Fatal("ExternalException with ErrorCode " + eex.ErrorCode + " has occurred when querying issued certificates", eex);
                throw;
            }
            catch (Exception ex)
            {
                log.Fatal("Error querying issued certificates", ex);
                throw;
            }

            if (null == dtCerts)
            {
                log.Info("No certificates found that have been issued before " + datIssuedEnd + " and haven't expired yet");
                return;
            }

            log.Info("Found " + dtCerts.Rows.Count + " certificates in the database issued before " + datIssuedEnd + ".");

            foreach (DataRow drIssuedCertificate in dtCerts.Rows)
            {
                log4net.ThreadContext.Properties.Clear();

                try
                {
                    repairIssuedCertificate(msca, drIssuedCertificate, fModifyDatabase);
                    log.Info("Successfully repaired a certificate");
                }
                catch (System.Runtime.InteropServices.ExternalException eex)
                {
                    log.Error("ExternalException with ErrorCode " + eex.ErrorCode + " has occurred when repairing an issued certificate. Proceeding with other certificates...", eex);
                }
                catch (Exception ex)
                {
                    log.Error("Error repairing an issued certificate. Proceeding with other certificates...", ex);
                }
            }
        }

        private static ILog _logIssuanceWorker;
        private static ILog logIssuanceWorker
        {
            get
            {
                if (null == _logIssuanceWorker)
                    _logIssuanceWorker = LogManager.GetLogger("GK.CACleaner.Console.repairIssued.Worker");
                return _logIssuanceWorker;
            }
        }

        private static void repairIssuedCertificate(CertificateServices msca, DataRow drIssuedCertificate, bool fModifyDatabase)
        {
            // TODO: Lots of code copied from repairRevokedCertificate
            int iRequestID = (int)drIssuedCertificate["RequestID"];
            log4net.ThreadContext.Properties["RequestID.Old"] = iRequestID;
            string sSerial = drIssuedCertificate["SerialNumber"].ToString();
            log4net.ThreadContext.Properties["SerialNumber"] = sSerial;
            string sCertificate = (string)drIssuedCertificate["RawCertificate"];

            logIssuanceWorker.Debug("Certificate (Serial " + sSerial + ", size " + sCertificate.Length + " bytes) found for repair");

            if (logIssuanceWorker.IsDebugEnabled)
            {
                System.Security.Cryptography.X509Certificates.X509Certificate2 cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                    System.Text.Encoding.ASCII.GetBytes(sCertificate)
                );
                logIssuanceWorker.Debug("Certificate decoded with subject \"" + cert.Subject + "\"");
            }

            if (fModifyDatabase)
            {
                msca.deleteCertificateRow(iRequestID);

                logIssuanceWorker.Debug("Certificate was deleted from database");

                try
                {
                    int iNewRequestID = msca.importCertificate(sCertificate);
                    log4net.ThreadContext.Properties["RequestID.New"] = iNewRequestID;
                }
                catch (Exception ex)
                {
                    logIssuanceWorker.Error("Could not re-import certificate. RawCertificate:\n" + sCertificate, ex);
                    throw;
                }

                logIssuanceWorker.Debug("Certificate was reimported into database");
            }
        }

        static void listAllADCertificateTemplates()
        {
            ILog log = LogManager.GetLogger("GK.CACleaner.Console.CertificateTemplates");
            log.Info("Starting to list certificate templates available in AD (this feature has preview status)");

            CertificateTemplate[] userTemplates = CertificateTemplate.RetrieveAllUserCertificateTemplates();

            foreach (CertificateTemplate ct in userTemplates)
                log.Info("Certificate Template \"" + ct.TemplateName + "\" found with OID \"" + ct.TemplateOID + "\" (type " + ct.TemplateType + ")");

            CertificateTemplate[] machineTemplates = CertificateTemplate.RetrieveAllMachineCertificateTemplates();

            foreach (CertificateTemplate ct in machineTemplates)
                log.Info("Certificate Template \"" + ct.TemplateName + "\" found with OID \"" + ct.TemplateOID + "\" (type " + ct.TemplateType + ")");

            log.Info("Finished listing certificate templates available in AD");
        }
    }
}
