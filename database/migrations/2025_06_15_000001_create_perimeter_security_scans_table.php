<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        // Get the configured table prefix
        $prefix = Config::get('perimeter.storage.table_prefix', 'perimeter_');

        Schema::create($prefix.'security_scans', function (Blueprint $table) {
            $table->id();
            $table->string('scan_type')->index();
            $table->timestamp('started_at');
            $table->timestamp('completed_at')->nullable();
            $table->string('status')->default('pending')->index();
            $table->integer('issues_found')->default(0);
            $table->json('scan_details')->nullable();
            $table->string('command')->nullable();
            $table->json('command_options')->nullable();
            $table->timestamps();

            // Indexes for efficient querying
            $table->index('started_at');
            $table->index('created_at');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        // Get the configured table prefix
        $prefix = Config::get('perimeter.storage.table_prefix', 'perimeter_');

        Schema::dropIfExists($prefix.'security_scans');
    }
};
