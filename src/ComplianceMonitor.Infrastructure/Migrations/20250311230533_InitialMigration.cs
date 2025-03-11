using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ComplianceMonitor.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class InitialMigration : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ImageScans",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ImageName = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    ScanTime = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Metadata = table.Column<string>(type: "nvarchar(max)", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ImageScans", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Policies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Description = table.Column<string>(type: "nvarchar(500)", maxLength: 500, nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RuleType = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Parameters = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsEnabled = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    UpdatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Policies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Resources",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Kind = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Name = table.Column<string>(type: "nvarchar(253)", maxLength: 253, nullable: false),
                    Namespace = table.Column<string>(type: "nvarchar(253)", maxLength: 253, nullable: false),
                    Uid = table.Column<string>(type: "nvarchar(36)", maxLength: 36, nullable: false),
                    Labels = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Annotations = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Spec = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Resources", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ImageScanResultId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PackageName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: false),
                    InstalledVersion = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    FixedVersion = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Severity = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Description = table.Column<string>(type: "nvarchar(2000)", maxLength: 2000, nullable: false),
                    References = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CvssScore = table.Column<double>(type: "float", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => new { x.Id, x.ImageScanResultId });
                    table.ForeignKey(
                        name: "FK_Vulnerabilities_ImageScans_ImageScanResultId",
                        column: x => x.ImageScanResultId,
                        principalTable: "ImageScans",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ComplianceChecks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    PolicyId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ResourceId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Status = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    Details = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ComplianceChecks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ComplianceChecks_Policies_PolicyId",
                        column: x => x.PolicyId,
                        principalTable: "Policies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ComplianceChecks_Resources_ResourceId",
                        column: x => x.ResourceId,
                        principalTable: "Resources",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Alerts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ComplianceCheckId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Acknowledged = table.Column<bool>(type: "bit", nullable: false),
                    AcknowledgedBy = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    AcknowledgedAt = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Alerts", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Alerts_ComplianceChecks_ComplianceCheckId",
                        column: x => x.ComplianceCheckId,
                        principalTable: "ComplianceChecks",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_Acknowledged",
                table: "Alerts",
                column: "Acknowledged");

            migrationBuilder.CreateIndex(
                name: "IX_Alerts_ComplianceCheckId",
                table: "Alerts",
                column: "ComplianceCheckId");

            migrationBuilder.CreateIndex(
                name: "IX_ComplianceChecks_PolicyId",
                table: "ComplianceChecks",
                column: "PolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_ComplianceChecks_ResourceId",
                table: "ComplianceChecks",
                column: "ResourceId");

            migrationBuilder.CreateIndex(
                name: "IX_ComplianceChecks_Status",
                table: "ComplianceChecks",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_ImageScans_ImageName",
                table: "ImageScans",
                column: "ImageName");

            migrationBuilder.CreateIndex(
                name: "IX_Policies_IsEnabled",
                table: "Policies",
                column: "IsEnabled");

            migrationBuilder.CreateIndex(
                name: "IX_Policies_Name",
                table: "Policies",
                column: "Name");

            migrationBuilder.CreateIndex(
                name: "IX_Policies_RuleType",
                table: "Policies",
                column: "RuleType");

            migrationBuilder.CreateIndex(
                name: "IX_Resources_Kind",
                table: "Resources",
                column: "Kind");

            migrationBuilder.CreateIndex(
                name: "IX_Resources_Namespace",
                table: "Resources",
                column: "Namespace");

            migrationBuilder.CreateIndex(
                name: "IX_Resources_Uid",
                table: "Resources",
                column: "Uid",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_ImageScanResultId",
                table: "Vulnerabilities",
                column: "ImageScanResultId");

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_Severity",
                table: "Vulnerabilities",
                column: "Severity");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Alerts");

            migrationBuilder.DropTable(
                name: "Vulnerabilities");

            migrationBuilder.DropTable(
                name: "ComplianceChecks");

            migrationBuilder.DropTable(
                name: "ImageScans");

            migrationBuilder.DropTable(
                name: "Policies");

            migrationBuilder.DropTable(
                name: "Resources");
        }
    }
}
